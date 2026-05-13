/**
 * 파일 경로 → 어떤 manifest 파서를 쓸지 결정.
 */
import * as path from 'path';

import { DependencyMention } from './types';
import { parsePackageJson } from './packageJson';
import { parsePyprojectToml } from './pyprojectToml';
import { parseRequirementsTxt } from './requirementsTxt';

export type ManifestKind = 'package.json' | 'pyproject.toml' | 'requirements.txt';

export function detectManifest(filePath: string): ManifestKind | null {
  const base = path.basename(filePath).toLowerCase();
  if (base === 'package.json') return 'package.json';
  if (base === 'pyproject.toml') return 'pyproject.toml';
  if (
    base === 'requirements.txt' ||
    base.endsWith('-requirements.txt') ||
    base === 'requirements-dev.txt' ||
    base.endsWith('.requirements.txt')
  ) {
    return 'requirements.txt';
  }
  return null;
}

export function parseManifest(
  kind: ManifestKind,
  text: string,
): DependencyMention[] {
  switch (kind) {
    case 'package.json':
      return parsePackageJson(text);
    case 'pyproject.toml':
      return parsePyprojectToml(text);
    case 'requirements.txt':
      return parseRequirementsTxt(text);
  }
}
