/**
 * pkgsentinel HTTP 클라이언트.
 *
 *   POST /api/v1/analyze
 *
 * fetch (Node 18+) 사용 — 외부 의존성 없음. HMAC secret 이 비어있으면
 * unsigned 모드.
 */
import { signBody } from './hmac';
import { DependencyMention, Ecosystem } from '../manifest/types';

export type Verdict =
  | 'MALICIOUS'
  | 'HIGH_RISK'
  | 'SUSPICIOUS'
  | 'CLEAN'
  | 'UNKNOWN'
  | 'NETWORK_ERROR';

export interface AnalyzeResponse {
  ok: boolean;
  verdict?: Verdict;
  confidence?: number;
  reasoning?: string;
  evidence_count?: number;
  evidence_summary?: Array<{
    file_path?: string;
    line_start?: number;
    ttp_id?: string;
    ttp_name?: string;
    ttp_severity?: string;
    confidence?: number;
    llm_verdict?: string;
    code_snippet?: string;
  }>;
  cache?: { hit: boolean; reason?: string; cached_at?: string };
  elapsed_s?: number;
  error?: string;
}

export interface ClientOptions {
  serverUrl: string;
  hmacSecret: string;
  llmMode: 'stub' | 'claude';
  timeoutMs: number;
}

export interface AnalyzeRequest {
  pkg: DependencyMention;
}

export interface AnalyzeResult {
  pkg: DependencyMention;
  response: AnalyzeResponse;
  httpStatus: number;
}

const NETWORK_ERROR_RESP: AnalyzeResponse = {
  ok: false,
  verdict: 'NETWORK_ERROR',
  error: 'network error or timeout',
};

export class PkgsentinelClient {
  constructor(private opts: ClientOptions) {}

  /**
   * 단일 패키지 분석.
   */
  async analyze(pkg: DependencyMention): Promise<AnalyzeResult> {
    const payload: Record<string, unknown> = {
      package: pkg.name,
      ecosystem: pkg.ecosystem,
      llm_mode: this.opts.llmMode,
    };
    if (pkg.resolvedVersion) payload.version = pkg.resolvedVersion;

    const body = Buffer.from(JSON.stringify(payload), 'utf-8');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.opts.hmacSecret && this.opts.hmacSecret.length > 0) {
      const signed = signBody(this.opts.hmacSecret, body);
      Object.assign(headers, signed.headers);
    } else {
      headers['X-AISLOPSQ-Tool'] = 'pkgsentinel-vscode/0.1.0';
    }

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.opts.timeoutMs);

    try {
      const r = await fetch(this.url('/api/v1/analyze'), {
        method: 'POST',
        headers,
        body,
        signal: ctrl.signal,
      });
      const text = await r.text();
      let resp: AnalyzeResponse;
      try {
        resp = JSON.parse(text) as AnalyzeResponse;
      } catch {
        resp = { ok: false, error: `non-JSON response (status ${r.status}): ${text.slice(0, 200)}` };
      }
      return { pkg, response: resp, httpStatus: r.status };
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      return {
        pkg,
        response: { ...NETWORK_ERROR_RESP, error: err },
        httpStatus: 0,
      };
    } finally {
      clearTimeout(t);
    }
  }

  /**
   * 다중 패키지 — concurrency 제한 큐.
   */
  async analyzeMany(
    pkgs: DependencyMention[],
    concurrency: number,
    onResult?: (r: AnalyzeResult) => void,
  ): Promise<AnalyzeResult[]> {
    const results: AnalyzeResult[] = [];
    let idx = 0;
    const worker = async () => {
      while (idx < pkgs.length) {
        const i = idx++;
        const r = await this.analyze(pkgs[i]);
        results[i] = r;
        if (onResult) onResult(r);
      }
    };
    const workers = Array.from(
      { length: Math.max(1, Math.min(concurrency, pkgs.length)) },
      () => worker(),
    );
    await Promise.all(workers);
    return results;
  }

  /** healthz ping — 서버 살아있는지 확인 (status bar 용). */
  async healthz(): Promise<boolean> {
    try {
      const r = await fetch(this.url('/healthz'), { method: 'GET' });
      return r.ok;
    } catch {
      return false;
    }
  }

  private url(path: string): string {
    const base = this.opts.serverUrl.replace(/\/+$/, '');
    return base + path;
  }
}

// Ecosystem 표시는 외부에서 type-only 가져갈 수 있도록 re-export
export type { Ecosystem };
