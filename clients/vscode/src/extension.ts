/**
 * pkgsentinel VSCode extension entry.
 *
 * 활성화 시:
 *   - DiagnosticsManager + HoverProvider 등록
 *   - StatusBar 표시
 *   - 워크스페이스 매니페스트 자동 스캔 (열려있는 문서)
 *   - 저장 시 재스캔 (설정 가능)
 *
 * 명령:
 *   pkgsentinel.scanWorkspace — 모든 매니페스트 스캔
 *   pkgsentinel.scanFile      — 현재 매니페스트만 스캔
 *   pkgsentinel.clearCache    — globalState verdict 캐시 비우기
 *   pkgsentinel.showOutput    — 출력 채널 표시
 */
import * as vscode from 'vscode';

import { AnalyzeResponse, AnalyzeResult, PkgsentinelClient } from './client/api';
import { VerdictCache } from './cache';
import { DiagnosticsManager } from './providers/diagnostics';
import { PkgsentinelHoverProvider } from './providers/hover';
import { StatusBar } from './statusBar';
import { detectManifest, parseManifest } from './manifest/detector';
import { DependencyMention } from './manifest/types';

let output: vscode.OutputChannel;
let diags: DiagnosticsManager;
let statusBar: StatusBar;
let cache: VerdictCache;

interface Settings {
  serverUrl: string;
  hmacSecret: string;
  llmMode: 'stub' | 'claude';
  autoScanOnSave: boolean;
  maxConcurrent: number;
  cacheTtlMinutes: number;
  requestTimeoutSeconds: number;
}

function readSettings(): Settings {
  const c = vscode.workspace.getConfiguration('pkgsentinel');
  return {
    serverUrl: c.get<string>('serverUrl', 'http://localhost:8787'),
    hmacSecret: c.get<string>('hmacSecret', ''),
    llmMode: c.get<'stub' | 'claude'>('llmMode', 'stub'),
    autoScanOnSave: c.get<boolean>('autoScanOnSave', true),
    maxConcurrent: c.get<number>('maxConcurrent', 4),
    cacheTtlMinutes: c.get<number>('cacheTtlMinutes', 60),
    requestTimeoutSeconds: c.get<number>('requestTimeoutSeconds', 60),
  };
}

function buildClient(s: Settings): PkgsentinelClient {
  return new PkgsentinelClient({
    serverUrl: s.serverUrl,
    hmacSecret: s.hmacSecret,
    llmMode: s.llmMode,
    timeoutMs: s.requestTimeoutSeconds * 1000,
  });
}

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  const kind = detectManifest(doc.uri.fsPath);
  if (!kind) return;
  const mentions = parseManifest(kind, doc.getText());
  if (mentions.length === 0) {
    diags.clear(doc.uri);
    statusBar.done([]);
    return;
  }
  const s = readSettings();
  cache.setTtl(s.cacheTtlMinutes);
  statusBar.scanning(doc.fileName.split(/[\\/]/).pop() || '?', mentions.length);
  log(`scan ${doc.uri.fsPath} (${kind}) — ${mentions.length} deps`);

  // 캐시 분리
  const fromCache: AnalyzeResult[] = [];
  const toFetch: DependencyMention[] = [];
  for (const m of mentions) {
    const c = cache.get(m.name, m.ecosystem, m.resolvedVersion);
    if (c) {
      fromCache.push({ pkg: m, response: c, httpStatus: 200 });
    } else {
      toFetch.push(m);
    }
  }
  log(`  cache hits: ${fromCache.length}, fetch: ${toFetch.length}`);

  const client = buildClient(s);
  const fetched = toFetch.length > 0
    ? await client.analyzeMany(toFetch, s.maxConcurrent, (r) => {
        if (r.response.ok) {
          void cache.put(
            r.pkg.name,
            r.pkg.ecosystem,
            r.pkg.resolvedVersion,
            r.response,
          );
        }
      })
    : [];
  const all = [...fromCache, ...fetched];

  const map = new Map<string, AnalyzeResponse>();
  for (const r of all) map.set(r.pkg.name, r.response);

  diags.setForUri(doc.uri, mentions, map);
  statusBar.done(all);
  logResults(all);
}

function log(msg: string): void {
  const ts = new Date().toISOString().slice(11, 19);
  output.appendLine(`[${ts}] ${msg}`);
}

function logResults(rs: AnalyzeResult[]): void {
  for (const r of rs) {
    const v = r.response.verdict || '?';
    const c = r.response.cache?.hit ? ' [cached]' : '';
    const conf = r.response.confidence !== undefined
      ? ` (${(r.response.confidence * 100).toFixed(0)}%)`
      : '';
    log(`  ${r.pkg.ecosystem}/${r.pkg.name}${r.pkg.resolvedVersion ? '@' + r.pkg.resolvedVersion : ''}: ${v}${conf}${c}`);
  }
}

async function scanWorkspace(): Promise<void> {
  const patterns = ['**/package.json', '**/pyproject.toml', '**/requirements*.txt'];
  const uris: vscode.Uri[] = [];
  for (const pat of patterns) {
    const found = await vscode.workspace.findFiles(pat, '**/node_modules/**', 100);
    uris.push(...found);
  }
  if (uris.length === 0) {
    void vscode.window.showInformationMessage(
      'pkgsentinel: 워크스페이스에 매니페스트가 없습니다.',
    );
    return;
  }
  for (const uri of uris) {
    const doc = await vscode.workspace.openTextDocument(uri);
    await scanDocument(doc);
  }
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel('pkgsentinel');
  diags = new DiagnosticsManager();
  statusBar = new StatusBar();
  const s = readSettings();
  cache = new VerdictCache(context, s.cacheTtlMinutes * 60 * 1000);

  log(`pkgsentinel activated — server=${s.serverUrl} llm=${s.llmMode}`);

  // 매니페스트 언어 hover provider 등록
  const hoverProvider = new PkgsentinelHoverProvider(diags);
  for (const lang of ['json', 'toml', 'pip-requirements', 'plaintext']) {
    context.subscriptions.push(
      vscode.languages.registerHoverProvider(lang, hoverProvider),
    );
  }

  // 명령 등록
  context.subscriptions.push(
    vscode.commands.registerCommand('pkgsentinel.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('pkgsentinel.scanFile', async () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) {
        void vscode.window.showInformationMessage('pkgsentinel: 활성 파일 없음.');
        return;
      }
      await scanDocument(ed.document);
    }),
    vscode.commands.registerCommand('pkgsentinel.clearCache', async () => {
      await cache.clear();
      diags.clearAll();
      void vscode.window.showInformationMessage('pkgsentinel: 캐시 비움.');
    }),
    vscode.commands.registerCommand('pkgsentinel.showOutput', () => output.show()),
  );

  // 저장 시 자동 스캔
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (!readSettings().autoScanOnSave) return;
      if (!detectManifest(doc.uri.fsPath)) return;
      await scanDocument(doc);
    }),
  );

  // 닫힌 문서의 진단 정리
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => diags.clear(doc.uri)),
    diags,
    statusBar,
  );

  // 시작 시 — 워크스페이스 자동 스캔 (백그라운드)
  setTimeout(() => {
    void scanWorkspace();
  }, 500);
}

export function deactivate(): void {
  diags?.dispose();
  statusBar?.dispose();
  output?.dispose();
}
