"""
Package Threat Detection Engine V2

독자적 엔진 + LLM 이중 검증으로 패키지에서 위협 요소를 전문 탐지.

모든 패키지를 동일한 강도로 검증하며 (인기도/나이 무관),
판정은 반드시 공신력 있는 프레임워크(MITRE ATT&CK/ATLAS, OWASP LLM Top 10)
에 매칭된 Evidence 리스트로 뒷받침된다.
"""

__version__ = "2.0.0-alpha"
