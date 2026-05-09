"""
스테이지 실행 컨텍스트 매니저 — pipeline.py 보일러플레이트 제거.

기존 패턴 (스테이지마다 8~10줄):

    # ========== Stage XX: ... ==========
    try:
        ...본문...
        ctx.stage_results.append(StageResult(
            stage="stage_xx",
            success=True,
            payload={...},
        ))
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage="stage_xx",
            success=False,
            error=f"{e}\\n{traceback.format_exc()}",
        ))

새 패턴 (스테이지마다 4~6줄):

    # ========== Stage XX: ... ==========
    with stage(ctx, "stage_xx") as st:
        ...본문...
        st.payload = {...}

설계 원칙:
- 예외 발생 시 자동으로 success=False StageResult 생성. 본문에서 예외 다시 raise 하지 말 것.
- 스테이지가 자발적으로 skip 해야 하면 `st.skip()` 호출. StageResult 추가 안 됨.
- 본문이 직접 ctx.stage_results.append 하면 안 됨 (이중 기록 위험).
- payload 는 dict 권장. None 으로 두면 StageResult.payload 가 None.
- 본문이 ctx.evidence 를 추가하는 건 그대로 (컨텍스트 매니저 무관).
"""
from __future__ import annotations

import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from .schema import StageResult


@dataclass
class StageHolder:
    """with-block 안에서 stage 결과를 모으는 임시 컨테이너."""
    label: str
    payload: Optional[dict] = None
    success_override: Optional[bool] = None      # True/False 강제 지정용
    error_override: Optional[str] = None
    _skipped: bool = field(default=False, init=False)

    def skip(self) -> None:
        """이 스테이지를 결과에 기록하지 않음. early-return 조건에 사용."""
        self._skipped = True

    def fail(self, error: str) -> None:
        """본문 안에서 명시적 실패 기록 (예외 없이 실패 처리)."""
        self.success_override = False
        self.error_override = error


@contextmanager
def stage(ctx: Any, label: str) -> Iterator[StageHolder]:
    """스테이지 실행 컨텍스트.

    Args:
        ctx: stage_results 리스트를 가진 컨텍스트 (PipelineContext 등).
        label: 스테이지 식별자 (예: "stage_4c_indicator_matcher").

    Yields:
        StageHolder — payload 설정 / skip / fail 인터페이스.

    예외 처리:
        with-block 안에서 발생한 모든 예외는 catch 되어 StageResult(success=False)
        로 기록됨. 호출자에게 전파되지 않음.
    """
    holder = StageHolder(label=label)
    try:
        yield holder
    except Exception as e:
        ctx.stage_results.append(StageResult(
            stage=label,
            success=False,
            error=f"{e}\n{traceback.format_exc()}",
        ))
        return

    if holder._skipped:
        return

    success = (
        holder.success_override
        if holder.success_override is not None
        else True
    )
    ctx.stage_results.append(StageResult(
        stage=label,
        success=success,
        error=holder.error_override,
        payload=holder.payload,
    ))
