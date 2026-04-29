"""파이프라인 단계 사이의 간단한 조회/스니펫 헬퍼."""
from __future__ import annotations

from ..schema import LLMVerdict
from ..stages.stage2_behavior import BehaviorReport, FileSequence
from ..stages.stage4_ttp_match import TTPMatch


def find_file_seq(behavior: BehaviorReport, file_path: str) -> FileSequence | None:
    for fs in behavior.files:
        if fs.path == file_path:
            return fs
    return None


def snippet_for(file_seq: FileSequence, max_lines: int = 30) -> str:
    if not file_seq.calls:
        return ""
    return "\n".join(c.snippet for c in file_seq.calls[:max_lines])


def match_confidence(m: TTPMatch, llm_verdict: LLMVerdict) -> float:
    base = m.similarity
    if llm_verdict == LLMVerdict.MALICIOUS:
        return min(1.0, base + 0.10)
    if llm_verdict == LLMVerdict.SUSPICIOUS:
        return min(1.0, base + 0.05)
    return max(0.0, base - 0.05)
