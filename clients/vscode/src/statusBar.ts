/**
 * 상태바 — 서버 연결 + 마지막 스캔 요약.
 *
 *   $(shield) pkgsentinel — 12 ✓ / 1 ⚠ / 0 ⛔
 *
 * 클릭 시 출력 채널 열림.
 */
import * as vscode from 'vscode';

import { AnalyzeResult } from './client/api';

export class StatusBar {
  private item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    );
    this.item.command = 'pkgsentinel.showOutput';
    this.idle();
    this.item.show();
  }

  dispose(): void {
    this.item.dispose();
  }

  idle(): void {
    this.item.text = '$(shield) pkgsentinel';
    this.item.tooltip = 'pkgsentinel ready — scan a manifest.';
  }

  scanning(file: string, total: number): void {
    this.item.text = `$(sync~spin) pkgsentinel — scanning ${total} dep(s)`;
    this.item.tooltip = `Analyzing ${file}`;
  }

  done(results: AnalyzeResult[]): void {
    let clean = 0, susp = 0, bad = 0, neterr = 0;
    for (const r of results) {
      const v = r.response.verdict;
      if (v === 'MALICIOUS' || v === 'HIGH_RISK') bad++;
      else if (v === 'SUSPICIOUS') susp++;
      else if (v === 'NETWORK_ERROR') neterr++;
      else if (v === 'CLEAN') clean++;
    }
    const parts: string[] = [];
    if (bad > 0) parts.push(`${bad}⛔`);
    if (susp > 0) parts.push(`${susp}⚠`);
    if (clean > 0) parts.push(`${clean}✓`);
    if (neterr > 0) parts.push(`${neterr}🔌`);
    this.item.text =
      `$(shield) pkgsentinel — ` + (parts.length ? parts.join(' / ') : 'no deps');
    this.item.tooltip = `Last scan: ${results.length} package(s) analyzed.`;
  }

  serverDown(): void {
    this.item.text = '$(circle-slash) pkgsentinel — server down';
    this.item.tooltip = 'pkgsentinel server unreachable. Check serverUrl setting.';
  }
}
