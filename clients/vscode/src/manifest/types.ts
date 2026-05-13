/**
 * 매니페스트 파서가 추출하는 단위.
 *
 * 한 의존성 = {name, version, ecosystem, range} + 원문에서의 위치
 * (line/character) 정보. line/character 는 diagnostic squiggle 그리는 데 필수.
 */

export type Ecosystem = 'npm' | 'PyPI';

export interface DependencyMention {
  /** 패키지 이름 — 정규화 (npm: 그대로, PyPI: lower + dash) */
  name: string;
  /** 추출된 버전 또는 range (없으면 undefined) */
  versionSpec?: string;
  /** 평가 시 사용할 *구체* 버전 (range 의 경우 lower bound 추출; 미파악 시 latest) */
  resolvedVersion?: string;
  ecosystem: Ecosystem;
  /** 원문 라인 (0-based) — diagnostic 위치 */
  line: number;
  /** 라인 안 시작 컬럼 (0-based) */
  startChar: number;
  /** 라인 안 끝 컬럼 (이름 + range 전체) */
  endChar: number;
  /** dev/optional 인 경우 표시 — diagnostic severity 조정에 사용 가능 */
  dev?: boolean;
  /** 원문 그대로 (디버깅용) */
  rawLine?: string;
}
