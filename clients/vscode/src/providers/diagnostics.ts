/**
 * Diagnostics — 의존성 한 줄마다 squiggle.
 *
 * 색상:
 *   MALICIOUS / HIGH_RISK → Error (red squiggle)
 *   SUSPICIOUS            → Warning (yellow)
 *   CLEAN                 → 표시 안 함
 *   NETWORK_ERROR         → Information (회색)
 */
import * as vscode from 'vscode';

import { AnalyzeResponse, Verdict } from '../client/api';
import { DependencyMention } from '../manifest/types';

const SOURCE = 'pkgsentinel';

export class DiagnosticsManager {
  readonly collection: vscode.DiagnosticCollection;
  /** (uri.toString() → name → response) — hover provider 가 사용 */
  private store = new Map<string, Map<string, AnalyzeResponse>>();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('pkgsentinel');
  }

  dispose(): void {
    this.collection.dispose();
  }

  /** 한 문서의 진단을 *교체* (덮어쓰기). */
  setForUri(
    uri: vscode.Uri,
    mentions: DependencyMention[],
    responses: Map<string, AnalyzeResponse>,
  ): void {
    const diags: vscode.Diagnostic[] = [];
    const docStore = new Map<string, AnalyzeResponse>();

    for (const m of mentions) {
      const r = responses.get(m.name);
      if (!r) continue;
      docStore.set(m.name, r);
      const sev = severityFor(r.verdict);
      if (!sev) continue;
      const range = new vscode.Range(
        new vscode.Position(m.line, m.startChar),
        new vscode.Position(m.line, m.endChar),
      );
      const msg = formatMessage(m, r);
      const d = new vscode.Diagnostic(range, msg, sev);
      d.source = SOURCE;
      d.code = r.verdict;
      diags.push(d);
    }
    this.collection.set(uri, diags);
    this.store.set(uri.toString(), docStore);
  }

  /** hover provider 가 호출. 라인 위치로 응답을 조회. */
  responseAt(
    uri: vscode.Uri,
    mentions: DependencyMention[],
    position: vscode.Position,
  ): { mention: DependencyMention; response: AnalyzeResponse } | null {
    const map = this.store.get(uri.toString());
    if (!map) return null;
    for (const m of mentions) {
      if (
        m.line === position.line &&
        position.character >= m.startChar &&
        position.character <= m.endChar
      ) {
        const r = map.get(m.name);
        if (r) return { mention: m, response: r };
      }
    }
    return null;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.store.delete(uri.toString());
  }

  clearAll(): void {
    this.collection.clear();
    this.store.clear();
  }
}

function severityFor(v: Verdict | undefined): vscode.DiagnosticSeverity | null {
  switch (v) {
    case 'MALICIOUS':
    case 'HIGH_RISK':
      return vscode.DiagnosticSeverity.Error;
    case 'SUSPICIOUS':
      return vscode.DiagnosticSeverity.Warning;
    case 'NETWORK_ERROR':
      return vscode.DiagnosticSeverity.Information;
    default:
      return null;
  }
}

function formatMessage(m: DependencyMention, r: AnalyzeResponse): string {
  const v = r.verdict ?? 'UNKNOWN';
  if (v === 'NETWORK_ERROR') {
    return `pkgsentinel: 서버 연결 실패 (${r.error || 'unknown'}). 설정의 serverUrl 확인.`;
  }
  const conf = r.confidence !== undefined ? ` (conf ${(r.confidence * 100).toFixed(0)}%)` : '';
  const cache = r.cache?.hit ? ' [cached]' : '';
  const ttp = r.evidence_summary?.[0]?.ttp_name;
  const reason = r.reasoning?.split('\n')[0]?.slice(0, 140);
  return `${m.ecosystem}/${m.name}${m.resolvedVersion ? '@' + m.resolvedVersion : ''}: ${v}${conf}${cache}` +
    (ttp ? `  — ${ttp}` : '') +
    (reason ? `\n${reason}` : '');
}
