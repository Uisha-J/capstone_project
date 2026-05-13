"""Runtime threat intel feedback loop — IOC 추출 + 룰 생성 + 외부 export."""

from .extractor import (
    extract_iocs_from_event,
    extract_pattern_from_event,
    parse_event,
)
from .rule_generator import (
    generate_aislopsq_r_extension,
    generate_all_drafts,
    generate_falco_rule,
    generate_indicator_47_rule,
    generate_sequence_pattern_rule,
)

__all__ = [
    "parse_event",
    "extract_iocs_from_event",
    "extract_pattern_from_event",
    "generate_indicator_47_rule",
    "generate_falco_rule",
    "generate_sequence_pattern_rule",
    "generate_aislopsq_r_extension",
    "generate_all_drafts",
]
