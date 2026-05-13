/**
 * requirements.txt 파서 (pip 형식).
 *
 * 지원:
 *   pkg
 *   pkg==1.2.3
 *   pkg>=1.0,<2.0
 *   pkg[extra]==1.2.3
 *   pkg @ git+https://...   ← 표시는 하되 version 미파악
 *
 * 미지원/제외:
 *   -r other.txt
 *   --index-url ...
 *   # 주석
 *   빈 줄
 */
import { DependencyMention } from './types';

const LINE_RE =
  /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,\s-]*\])?\s*((?:==|>=|<=|~=|!=|>|<)?\s*[^\s;#]+)?/;

export function parseRequirementsTxt(text: string): DependencyMention[] {
  const out: DependencyMention[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (trimmed.startsWith('-')) continue;          // -r, --index-url, etc.
    if (trimmed.includes('@')) {
      // pkg @ git+... — name 만 잡음
      const at = trimmed.indexOf('@');
      const name = normalizePypi(trimmed.slice(0, at).trim());
      if (!name) continue;
      out.push({
        name,
        ecosystem: 'PyPI',
        line: i,
        startChar: raw.indexOf(trimmed),
        endChar: raw.length,
        rawLine: raw,
      });
      continue;
    }
    const m = LINE_RE.exec(trimmed);
    if (!m) continue;
    const name = normalizePypi(m[1]);
    if (!name) continue;
    const spec = (m[2] || '').trim();
    const startChar = raw.indexOf(m[1]);
    const endChar = startChar + (spec ? m[0].length : m[1].length);
    out.push({
      name,
      versionSpec: spec || undefined,
      resolvedVersion: extractConcreteVersionPypi(spec),
      ecosystem: 'PyPI',
      line: i,
      startChar: startChar >= 0 ? startChar : 0,
      endChar: endChar > startChar ? endChar : raw.length,
      rawLine: raw,
    });
  }
  return out;
}

/** PyPI 정규화 (PEP 503): lowercase + [_.] → '-' */
export function normalizePypi(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[_.]+/g, '-');
}

export function extractConcreteVersionPypi(spec: string): string | undefined {
  if (!spec) return undefined;
  const m = /(\d+(?:\.\d+)+(?:[ab.\-]?\d+)?)/.exec(spec);
  return m ? m[1] : undefined;
}
