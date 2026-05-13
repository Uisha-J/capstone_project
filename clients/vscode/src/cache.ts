/**
 * 클라이언트 측 verdict 캐시 — globalState 기반.
 *
 * 같은 (name, ecosystem, version) 에 대해 N분 이내 결과는 재사용. 서버
 * 측에도 캐시가 있지만 클라이언트 캐시는 *네트워크 호출 자체* 를 절약.
 */
import * as vscode from 'vscode';

import { AnalyzeResponse } from './client/api';

interface CachedVerdict {
  response: AnalyzeResponse;
  storedAt: number;
}

const KEY = 'pkgsentinel.verdictCache.v1';

export class VerdictCache {
  constructor(private context: vscode.ExtensionContext, private ttlMs: number) {}

  private all(): Record<string, CachedVerdict> {
    return (
      (this.context.globalState.get(KEY) as Record<string, CachedVerdict>) || {}
    );
  }

  private async setAll(map: Record<string, CachedVerdict>): Promise<void> {
    await this.context.globalState.update(KEY, map);
  }

  key(name: string, ecosystem: string, version: string | undefined): string {
    return `${ecosystem}:${name}@${version ?? 'latest'}`;
  }

  get(name: string, ecosystem: string, version: string | undefined):
    | AnalyzeResponse
    | undefined {
    const map = this.all();
    const k = this.key(name, ecosystem, version);
    const c = map[k];
    if (!c) return undefined;
    if (Date.now() - c.storedAt > this.ttlMs) {
      delete map[k];
      void this.setAll(map);
      return undefined;
    }
    return c.response;
  }

  async put(
    name: string,
    ecosystem: string,
    version: string | undefined,
    response: AnalyzeResponse,
  ): Promise<void> {
    if (!response.ok) return;   // 실패 응답은 캐시하지 않음
    if (response.verdict === 'NETWORK_ERROR') return;
    const map = this.all();
    map[this.key(name, ecosystem, version)] = {
      response,
      storedAt: Date.now(),
    };
    await this.setAll(map);
  }

  async clear(): Promise<void> {
    await this.setAll({});
  }

  setTtl(minutes: number): void {
    this.ttlMs = minutes * 60 * 1000;
  }
}
