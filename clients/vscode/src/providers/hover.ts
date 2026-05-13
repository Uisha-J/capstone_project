/**
 * Hover provider — 의존성 줄에 hover 시 verdict + evidence 상세 표시.
 */
import * as vscode from 'vscode';

import { AnalyzeResponse, Verdict } from '../client/api';
import { DiagnosticsManager } from './diagnostics';
import { detectManifest, parseManifest } from '../manifest/detector';
import { DependencyMention } from '../manifest/types';

export class PkgsentinelHoverProvider implements vscode.HoverProvider {
  constructor(private diags: DiagnosticsManager) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.ProviderResult<vscode.Hover> {
    const kind = detectManifest(document.uri.fsPath);
    if (!kind) return null;
    const mentions = parseManifest(kind, document.getText());
    const hit = this.diags.responseAt(document.uri, mentions, position);
    if (!hit) return null;
    return new vscode.Hover(buildMarkdown(hit.mention, hit.response));
  }
}

function emoji(v: Verdict | undefined): string {
  switch (v) {
    case 'MALICIOUS': return '🛑';
    case 'HIGH_RISK': return '⛔';
    case 'SUSPICIOUS': return '⚠️';
    case 'CLEAN': return '✅';
    case 'NETWORK_ERROR': return '🔌';
    default: return '❓';
  }
}

function buildMarkdown(
  m: DependencyMention,
  r: AnalyzeResponse,
): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.supportHtml = false;
  md.isTrusted = false;
  const v = r.verdict ?? 'UNKNOWN';

  md.appendMarkdown(`### ${emoji(v)} pkgsentinel — ${v}\n`);
  md.appendMarkdown(
    `**${m.ecosystem}** \`${m.name}${m.resolvedVersion ? '@' + m.resolvedVersion : ''}\`\n\n`,
  );

  if (r.confidence !== undefined) {
    md.appendMarkdown(`- **Confidence**: ${(r.confidence * 100).toFixed(0)}%\n`);
  }
  if (r.cache) {
    const tag = r.cache.hit ? '🗄️ cached' : 'fresh';
    md.appendMarkdown(`- **Cache**: ${tag}${r.cache.reason ? ` (${r.cache.reason})` : ''}\n`);
  }
  if (r.evidence_count !== undefined) {
    md.appendMarkdown(`- **Evidence**: ${r.evidence_count} signal(s)\n`);
  }
  if (r.elapsed_s !== undefined) {
    md.appendMarkdown(`- **Elapsed**: ${r.elapsed_s.toFixed(2)}s\n`);
  }

  if (r.reasoning) {
    md.appendMarkdown(`\n#### Reasoning\n`);
    md.appendMarkdown(r.reasoning.slice(0, 800).replace(/\n/g, '  \n'));
    md.appendMarkdown('\n');
  }

  if (r.evidence_summary?.length) {
    md.appendMarkdown(`\n#### Top evidence\n`);
    for (const e of r.evidence_summary.slice(0, 3)) {
      const file = e.file_path ?? '?';
      const line = e.line_start !== undefined ? `:${e.line_start}` : '';
      const ttp = e.ttp_name ?? e.ttp_id ?? '?';
      const sev = e.ttp_severity ? ` [${e.ttp_severity}]` : '';
      md.appendMarkdown(`- \`${file}${line}\` — **${ttp}**${sev}\n`);
      if (e.code_snippet) {
        const snip = e.code_snippet.slice(0, 200).replace(/`/g, '\\`');
        md.appendCodeblock(snip, m.ecosystem === 'npm' ? 'javascript' : 'python');
      }
    }
  }

  if (r.error) {
    md.appendMarkdown(`\n_${r.error}_\n`);
  }

  return md;
}
