/**
 * HMAC-SHA256 서명. 서버 측 `pkgsentinel.realtime.sinks.webhook_sink.hmac_sign`
 * 과 *완전히 동일* 한 byte-level 알고리즘.
 *
 *     msg = `${timestamp_ms}.` + body_bytes
 *     sig = HMAC_SHA256(secret, msg).hex()
 *     header = `sha256=${sig}`
 */
import * as crypto from 'crypto';

export interface SignedHeaders {
  'Content-Type': string;
  'X-AISLOPSQ-Signature': string;
  'X-AISLOPSQ-Timestamp': string;
  'X-AISLOPSQ-Tool': string;
}

export function signBody(
  secret: string,
  body: Buffer,
  timestampMs?: number,
): { headers: SignedHeaders; timestampMs: number } {
  const ts = timestampMs ?? Date.now();
  const prefix = Buffer.from(`${ts}.`, 'utf-8');
  const msg = Buffer.concat([prefix, body]);
  const sig = crypto.createHmac('sha256', secret).update(msg).digest('hex');
  return {
    timestampMs: ts,
    headers: {
      'Content-Type': 'application/json',
      'X-AISLOPSQ-Signature': `sha256=${sig}`,
      'X-AISLOPSQ-Timestamp': String(ts),
      'X-AISLOPSQ-Tool': 'pkgsentinel-vscode/0.1.0',
    },
  };
}
