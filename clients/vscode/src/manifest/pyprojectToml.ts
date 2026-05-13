/**
 * pyproject.toml 파서 — *간이* 라인 기반.
 *
 * 본격적인 TOML AST 파서 (예: @iarna/toml) 를 의존성에 추가하지 않고
 * 우리가 필요한 두 섹션만 처리.
 *
 * 지원:
 *   [project] dependencies = [ "requests>=2", "flask==3.0" ]
 *   [project.optional-dependencies] dev = [ "pytest" ]
 *   [tool.poetry.dependencies] requests = "^2.0"  / requests = {version="^2"}
 *   [tool.poetry.dev-dependencies] pytest = "*"
 *
 * 미지원:
 *   inline table 깊은 매칭, 멀티라인 string 등 edge case.
 */
import { DependencyMention } from './types';
import {
  extractConcreteVersionPypi,
  normalizePypi,
} from './requirementsTxt';

type Section =
  | 'project_deps'           // [project] dependencies = [...]
  | 'project_optional'       // [project.optional-dependencies]
  | 'poetry_deps'            // [tool.poetry.dependencies]
  | 'poetry_dev_deps'        // [tool.poetry.dev-dependencies] / .group.dev.dependencies
  | 'none';

export function parsePyprojectToml(text: string): DependencyMention[] {
  const out: DependencyMention[] = [];
  const lines = text.split(/\r?\n/);
  let section: Section = 'none';
  let inProjectDeps = false;             // [project] 본문에서 dependencies = [
  let projectDepsBracketOpen = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // 섹션 헤더?
    const sectionMatch = /^\[([A-Za-z0-9_.\-]+)\]/.exec(trimmed);
    if (sectionMatch) {
      const name = sectionMatch[1];
      inProjectDeps = false;
      projectDepsBracketOpen = false;
      if (name === 'project') section = 'project_deps';
      else if (name === 'project.optional-dependencies') section = 'project_optional';
      else if (name === 'tool.poetry.dependencies') section = 'poetry_deps';
      else if (
        name === 'tool.poetry.dev-dependencies' ||
        name.startsWith('tool.poetry.group.')
      )
        section = 'poetry_dev_deps';
      else section = 'none';
      continue;
    }

    // [project] dependencies = [ ... ]
    if (section === 'project_deps') {
      const startDeps = /^dependencies\s*=\s*\[/.exec(trimmed);
      if (startDeps) {
        inProjectDeps = true;
        projectDepsBracketOpen = !trimmed.includes(']');
        // 같은 줄에 첫 entry 있을 수 있음
        const inline = /\[\s*(.*?)\s*\]?$/.exec(trimmed)?.[1] ?? '';
        const items = splitTomlInlineList(inline);
        for (const it of items) addPypiSpec(out, it, i, raw);
        if (!projectDepsBracketOpen) inProjectDeps = false;
        continue;
      }
      if (inProjectDeps) {
        if (trimmed === ']') {
          inProjectDeps = false;
          projectDepsBracketOpen = false;
          continue;
        }
        // 한 줄 = 하나의 spec
        const it = stripTomlQuotesAndComma(trimmed);
        if (it) addPypiSpec(out, it, i, raw);
        continue;
      }
    }

    // [project.optional-dependencies] group = ["pkg>=1"]
    if (section === 'project_optional') {
      const m = /^[A-Za-z0-9_\-]+\s*=\s*\[(.*)\]\s*$/.exec(trimmed);
      if (m) {
        const items = splitTomlInlineList(m[1]);
        for (const it of items) addPypiSpec(out, it, i, raw, true);
      }
      continue;
    }

    // poetry
    if (section === 'poetry_deps' || section === 'poetry_dev_deps') {
      // requests = "^2.0"   |   requests = {version="^2", extras=["x"]}
      const m = /^([A-Za-z0-9._\-]+)\s*=\s*(.+)$/.exec(trimmed);
      if (!m) continue;
      const rawName = m[1];
      if (rawName.toLowerCase() === 'python') continue;   // python 자체는 skip
      const name = normalizePypi(rawName);
      const rest = m[2].trim();
      let versionSpec: string | undefined;
      const strLit = /^["']([^"']*)["']/.exec(rest);
      if (strLit) versionSpec = strLit[1];
      else {
        const verInline = /version\s*=\s*["']([^"']+)["']/.exec(rest);
        if (verInline) versionSpec = verInline[1];
      }
      const startChar = raw.indexOf(rawName);
      out.push({
        name,
        versionSpec,
        resolvedVersion: versionSpec
          ? extractConcreteVersionPypi(versionSpec)
          : undefined,
        ecosystem: 'PyPI',
        line: i,
        startChar: startChar >= 0 ? startChar : 0,
        endChar: raw.length,
        dev: section === 'poetry_dev_deps',
        rawLine: raw,
      });
    }
  }
  return out;
}

function splitTomlInlineList(s: string): string[] {
  // "a>=1", "b<2", "c"
  const out: string[] = [];
  const re = /"([^"]+)"|'([^']+)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    out.push(m[1] ?? m[2]);
  }
  return out;
}

function stripTomlQuotesAndComma(s: string): string | null {
  // "pkg>=1" ,   →  pkg>=1
  // "black; python_version >= '3.10'" 처럼 outer 가 " 이고 inner 가 '
  // 인 경우 모두 처리해야 함 → outer quote 종류에 따라 inner class 를 분기.
  const t = s.trim().replace(/,\s*$/, '');
  if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) {
    return t.slice(1, -1);
  }
  if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) {
    return t.slice(1, -1);
  }
  return null;
}

function addPypiSpec(
  out: DependencyMention[],
  spec: string,
  line: number,
  raw: string,
  dev = false,
) {
  // "requests>=2.0; python_version >= '3.8'" 같은 PEP-508 환경 표시 제거
  const env = spec.split(';')[0].trim();
  const m = /^([A-Za-z0-9][A-Za-z0-9._\-]*)/.exec(env);
  if (!m) return;
  const name = normalizePypi(m[1]);
  const versionSpec = env.slice(m[1].length).trim();
  const startChar = raw.indexOf(spec) >= 0 ? raw.indexOf(spec) : 0;
  out.push({
    name,
    versionSpec: versionSpec || undefined,
    resolvedVersion: versionSpec
      ? extractConcreteVersionPypi(versionSpec)
      : undefined,
    ecosystem: 'PyPI',
    line,
    startChar,
    endChar: startChar + spec.length,
    dev,
    rawLine: raw,
  });
}
