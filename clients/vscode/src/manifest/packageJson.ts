/**
 * package.json 파서.
 *
 * 일반적인 JSON.parse 는 line/character 정보를 잃기 때문에, dependencies /
 * devDependencies / optionalDependencies / peerDependencies 객체의 위치를
 * 별도 regex 로 잡은 뒤 그 안의 "name": "range" 한 줄 한 줄을 다시 매칭.
 *
 * 한계: JSON5 / 주석 / 트레일링 콤마는 지원 안 함 (표준 package.json 만).
 */
import { DependencyMention } from './types';

const DEP_SECTIONS: Array<{ key: string; dev: boolean }> = [
  { key: 'dependencies', dev: false },
  { key: 'devDependencies', dev: true },
  { key: 'optionalDependencies', dev: false },
  { key: 'peerDependencies', dev: false },
];

/** 한 줄에서 `"name": "range"` 패턴을 매칭. */
const LINE_RE = /^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*,?\s*$/;

export function parsePackageJson(text: string): DependencyMention[] {
  const lines = text.split(/\r?\n/);
  const out: DependencyMention[] = [];

  // 각 섹션 시작/끝 라인 추적
  for (const section of DEP_SECTIONS) {
    const range = findSectionRange(lines, section.key);
    if (!range) continue;
    for (let i = range.start + 1; i < range.end; i++) {
      const line = lines[i];
      const m = LINE_RE.exec(line);
      if (!m) continue;
      const name = m[1];
      const versionSpec = m[2];
      const startChar = line.indexOf('"' + name + '"');
      const endChar = line.lastIndexOf('"') + 1;
      out.push({
        name,
        versionSpec,
        resolvedVersion: extractConcreteVersionNpm(versionSpec),
        ecosystem: 'npm',
        line: i,
        startChar: startChar >= 0 ? startChar : 0,
        endChar: endChar > startChar ? endChar : line.length,
        dev: section.dev,
        rawLine: line,
      });
    }
  }
  return out;
}

function findSectionRange(
  lines: string[],
  key: string,
): { start: number; end: number } | null {
  const openRe = new RegExp(`^\\s*"${escapeRe(key)}"\\s*:\\s*\\{\\s*$`);
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (openRe.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  // depth 1 부터 시작. 동일 라인 안 } 가 다양하게 등장 가능하나 표준 포맷은
  // 한 줄에 하나만 — 단순 line-level 매칭으로 충분.
  let depth = 1;
  for (let i = start + 1; i < lines.length; i++) {
    if (/\{\s*$/.test(lines[i])) depth++;
    if (/^\s*\}\s*,?\s*$/.test(lines[i])) {
      depth--;
      if (depth === 0) return { start, end: i };
    }
  }
  return null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * npm semver range → 구체 버전 추출.
 *   "1.2.3"        → "1.2.3"
 *   "^1.2.3"       → "1.2.3"
 *   "~1.2.3"       → "1.2.3"
 *   ">=1.2.3 <2"   → "1.2.3"
 *   "*", "latest"  → undefined (server 측에서 latest resolve)
 *   "github:..."   → undefined
 *   "file:..."     → undefined
 */
export function extractConcreteVersionNpm(spec: string): string | undefined {
  const s = spec.trim();
  if (!s || s === '*' || s === 'latest') return undefined;
  if (/^(?:github|file|git|http|npm|workspace):/i.test(s)) return undefined;
  // 우선 ^x.y.z / ~x.y.z / =x.y.z 패턴
  const m = /(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?/.exec(s);
  return m ? m[0] : undefined;
}
