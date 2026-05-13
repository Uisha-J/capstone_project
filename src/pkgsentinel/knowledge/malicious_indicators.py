"""
47개 악성 지표 카탈로그 (Statement-Level Taxonomy)

근거 논문:
  Unveiling Malicious Logic: Towards a Statement-Level Taxonomy and Dataset
  for Securing Python Packages (2025)
  https://arxiv.org/html/2512.12559v1

7개 카테고리 × 총 47개 세부 지표:
  - EXS (Execution Stage)        : 3
  - EXM (Execution Mechanism)    : 8
  - EXF (Exfiltration)           : 5
  - SYS (System Impact)          : 9
  - NET (Network Operations)     : 10
  - DEF (Defense Evasion)        : 6
  - MET (Metadata Manipulation)  : 6

기존 4 Attack Dimension 과 매핑되어 하위호환을 유지.
각 지표는 코드 패턴 (regex/AST) 또는 메타데이터 검사로 탐지 가능.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..schema import AttackDimension, Severity

# ─────────────────── 7개 카테고리 ───────────────────

class IndicatorCategory(str, Enum):
    EXECUTION_STAGE = "Execution Stage"
    EXECUTION_MECHANISM = "Execution Mechanism"
    EXFILTRATION = "Exfiltration"
    SYSTEM_IMPACT = "System Impact"
    NETWORK = "Network Operations"
    DEFENSE_EVASION = "Defense Evasion"
    METADATA = "Metadata Manipulation"


# ─────────────────── 지표 정의 ───────────────────

@dataclass
class MaliciousIndicator:
    """단일 악성 지표."""
    code: str                              # "EXS-001"
    name: str                              # "Import-Time Execution"
    category: IndicatorCategory
    description: str
    severity: Severity
    # 기존 4 Dimension 매핑 (하위 호환용)
    related_dimensions: list[AttackDimension] = field(default_factory=list)
    # 매칭에 활용할 키워드/패턴 힌트 (정확한 탐지는 별도 모듈)
    detection_hints: list[str] = field(default_factory=list)
    # MITRE TTP 매핑 (있는 경우)
    mitre_ttps: list[str] = field(default_factory=list)


# ─────────────────── 47개 지표 풀 정의 ───────────────────

INDICATORS: dict[str, MaliciousIndicator] = {}


def _add(ind: MaliciousIndicator) -> None:
    INDICATORS[ind.code] = ind


# ─── EXS: Execution Stage (3) ─────────────────────
_add(MaliciousIndicator(
    code="EXS-001",
    name="Import-Time Execution",
    category=IndicatorCategory.EXECUTION_STAGE,
    description="모듈 import 즉시 자동 실행되는 페이로드. 모듈 레벨 코드에 페이로드 임베드.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["module-level call", "__init__.py top-level"],
    mitre_ttps=["T1059"],
))
_add(MaliciousIndicator(
    code="EXS-002",
    name="Install-Time Execution",
    category=IndicatorCategory.EXECUTION_STAGE,
    description="setup.py 최상위에 배치된 코드가 패키지 설치 시 자동 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["setup.py top-level", "side effect on import"],
    mitre_ttps=["T1195.002"],
))
_add(MaliciousIndicator(
    code="EXS-003",
    name="Lifecycle Hook Hijack",
    category=IndicatorCategory.EXECUTION_STAGE,
    description="setuptools install/develop 등 표준 설치 훅을 오버라이드하여 빌드 단계에 악성 로직 주입.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["cmdclass=", "install.run override", "build_py override"],
    mitre_ttps=["T1546"],
))


# ─── EXM: Execution Mechanism (8) ─────────────────
_add(MaliciousIndicator(
    code="EXM-001",
    name="Dynamic Evaluation",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="eval()/exec() 로 문자열에 담긴 코드를 동적 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["eval(", "exec(", "compile(... 'exec')"],
    mitre_ttps=["T1059.006"],
))
_add(MaliciousIndicator(
    code="EXM-002",
    name="Conditional Payload Trigger",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="OS/시간/환경 조건에 따라 조건부 실행 (분석 회피).",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["platform.system()", "sys.platform", "datetime check"],
    mitre_ttps=["T1480"],
))
_add(MaliciousIndicator(
    code="EXM-003",
    name="Binary Execution",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="번들된 컴파일 바이너리를 실행하여 Python 레벨 탐지 우회.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["subprocess + .so/.dll/.exe", "ctypes.CDLL"],
    mitre_ttps=["T1027.002"],
))
_add(MaliciousIndicator(
    code="EXM-004",
    name="Hidden Code Execution",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="백그라운드/숨김 모드로 서브프로세스 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["DETACHED_PROCESS", "creationflags", "nohup", "&"],
    mitre_ttps=["T1564"],
))
_add(MaliciousIndicator(
    code="EXM-005",
    name="Dynamic Module Import",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="동적 구성된 문자열로 모듈 import (난독화 가능성).",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["__import__(variable)", "importlib.import_module(variable)"],
    mitre_ttps=["T1027"],
))
_add(MaliciousIndicator(
    code="EXM-006",
    name="Dynamic Package Install",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="런타임에 pip install 등으로 의존성을 동적 설치.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION, AttackDimension.DATA_TRANSMISSION],
    detection_hints=["subprocess(['pip','install'", "pip.main"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="EXM-007",
    name="Script File Execution",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="번들된 외부 스크립트(Bash/PowerShell/Python) 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["subprocess + .sh/.ps1/.py", "os.system + script"],
    mitre_ttps=["T1059"],
))
_add(MaliciousIndicator(
    code="EXM-008",
    name="Shell Command Execution",
    category=IndicatorCategory.EXECUTION_MECHANISM,
    description="OS 셸로 raw 명령어 문자열 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["os.system(", "subprocess(shell=True", "popen("],
    mitre_ttps=["T1059.004"],
))


# ─── EXF: Exfiltration (5) ────────────────────────
_add(MaliciousIndicator(
    code="EXF-001",
    name="Data Exfiltration",
    category=IndicatorCategory.EXFILTRATION,
    description="자격증명/API 키 등 표적 민감 정보 외부 전송.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.INFORMATION_READING, AttackDimension.DATA_TRANSMISSION],
    detection_hints=["os.environ + http.post", "AWS_ACCESS_KEY", "GITHUB_TOKEN"],
    mitre_ttps=["T1552", "T1048"],
))
_add(MaliciousIndicator(
    code="EXF-002",
    name="File Exfiltration",
    category=IndicatorCategory.EXFILTRATION,
    description="파일 전체를 외부로 전송.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.INFORMATION_READING, AttackDimension.DATA_TRANSMISSION],
    detection_hints=["read file + http upload", "multipart/form-data"],
    mitre_ttps=["T1041"],
))
_add(MaliciousIndicator(
    code="EXF-003",
    name="DNS Tunneling",
    category=IndicatorCategory.EXFILTRATION,
    description="DNS 쿼리로 데이터 유출 또는 C2 트래픽 송신.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["socket.gethostbyname(encoded)", "dns.resolver.query"],
    mitre_ttps=["T1071.004"],
))
_add(MaliciousIndicator(
    code="EXF-004",
    name="Webhook Exfiltration",
    category=IndicatorCategory.EXFILTRATION,
    description="Slack/Discord/Telegram 등 채팅 API 를 은밀 채널로 사용.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["discord.com/api/webhooks", "hooks.slack.com", "api.telegram.org"],
    mitre_ttps=["T1567.002"],
))
_add(MaliciousIndicator(
    code="EXF-005",
    name="Suspicious Domain Exfiltration",
    category=IndicatorCategory.EXFILTRATION,
    description="악성 활동과 연관된 도메인으로 데이터 송신.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["pastebin.com", "transfer.sh", ".onion", "burp collaborator"],
    mitre_ttps=["T1041"],
))


# ─── SYS: System Impact (9) ────────────────────────
_add(MaliciousIndicator(
    code="SYS-001",
    name="Environment Modification",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="PATH, LD_PRELOAD 등 환경변수 변경.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["os.environ['PATH']=", "os.environ['LD_PRELOAD']="],
    mitre_ttps=["T1574"],
))
_add(MaliciousIndicator(
    code="SYS-002",
    name="Startup File Persistence",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="auto-start 위치 변경으로 부팅/로그인 시 실행되도록 영구화.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=[".bashrc", "Run registry key", "crontab", "systemd"],
    mitre_ttps=["T1547"],
))
_add(MaliciousIndicator(
    code="SYS-003",
    name="Crypto Wallet Harvesting",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="암호화폐 지갑 파일 / 키스토어 스캔.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.INFORMATION_READING],
    detection_hints=["wallet.dat", "keystore", "MetaMask", ".electrum"],
    mitre_ttps=["T1005"],
))
_add(MaliciousIndicator(
    code="SYS-004",
    name="Directory Enumeration",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="고가치 타겟 식별을 위한 파일시스템 열거.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.INFORMATION_READING],
    detection_hints=["os.walk", "glob.glob", "Path.rglob"],
    mitre_ttps=["T1083"],
))
_add(MaliciousIndicator(
    code="SYS-005",
    name="System Info Reconnaissance",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="시스템 메타데이터/사용자 정보 수집.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.INFORMATION_READING],
    detection_hints=["platform.uname", "getpass.getuser", "socket.gethostname"],
    mitre_ttps=["T1082"],
))
_add(MaliciousIndicator(
    code="SYS-006",
    name="File Relocation",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="영구화/숨김 위치로 파일 이동.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["shutil.move", "os.rename to AppData", "/tmp -> persistent"],
    mitre_ttps=["T1564"],
))
_add(MaliciousIndicator(
    code="SYS-007",
    name="File Deletion",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="흔적 제거를 위한 파일 삭제.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["os.remove", "os.unlink", "shutil.rmtree", "del /F"],
    mitre_ttps=["T1070.004"],
))
_add(MaliciousIndicator(
    code="SYS-008",
    name="Arbitrary File Write",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="페이로드 stage 또는 운영 데이터 영구화를 위해 임의 파일 작성.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["open(... 'w')", "Path.write_bytes", "with binary content"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="SYS-009",
    name="Sensitive Path Write",
    category=IndicatorCategory.SYSTEM_IMPACT,
    description="권한 필요한 시스템 경로에 쓰기 (system32, /etc, /usr/bin 등).",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["/etc/", "C:\\Windows\\System32", "/usr/bin/", "/Library/"],
    mitre_ttps=["T1105"],
))


# ─── NET: Network Operations (10) ─────────────────
_add(MaliciousIndicator(
    code="NET-001",
    name="Geolocation Lookup",
    category=IndicatorCategory.NETWORK,
    description="외부 IP 조회 API 로 피해자 위치 데이터 수집.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["ipinfo.io", "ip-api.com", "ipify.org", "ifconfig.me"],
    mitre_ttps=["T1614"],
))
_add(MaliciousIndicator(
    code="NET-002",
    name="Mining Pool Connection",
    category=IndicatorCategory.NETWORK,
    description="암호화폐 마이닝 풀 연결.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["stratum+tcp://", "xmr-pool", "minexmr.com", "supportxmr.com"],
    mitre_ttps=["T1496"],
))
_add(MaliciousIndicator(
    code="NET-003",
    name="Suspicious Connection",
    category=IndicatorCategory.NETWORK,
    description="공격자 통제 또는 신규 등록된 도메인으로 연결.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["typosquatted hostname", "newly registered domain"],
    mitre_ttps=["T1071"],
))
_add(MaliciousIndicator(
    code="NET-004",
    name="Archive Dropper",
    category=IndicatorCategory.NETWORK,
    description="원격 서버에서 압축 아카이브를 받아 로컬 해제.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["zipfile + urlopen", "tarfile + http", "extractall"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="NET-005",
    name="Binary Dropper",
    category=IndicatorCategory.NETWORK,
    description="원격 서버에서 컴파일된 실행파일 다운로드.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=[".exe download", ".dll fetch", ".so + write binary"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="NET-006",
    name="Payload Dropper",
    category=IndicatorCategory.NETWORK,
    description="설치 후 원격 서버에서 악성 페이로드 가져오기.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["urlopen + exec", "requests.get + eval"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="NET-007",
    name="Script Dropper",
    category=IndicatorCategory.NETWORK,
    description="원격에서 인터프리터 스크립트를 받아 로컬 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["curl | bash", "python -c \"$(curl ...)\"", "iex(iwr"],
    mitre_ttps=["T1105"],
))
_add(MaliciousIndicator(
    code="NET-008",
    name="Reverse Shell",
    category=IndicatorCategory.NETWORK,
    description="공격자 통제 서버로 역방향 셸 연결 수립.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["socket.connect + dup2 + exec", "/dev/tcp/"],
    mitre_ttps=["T1059"],
))
_add(MaliciousIndicator(
    code="NET-009",
    name="SSL Validation Bypass",
    category=IndicatorCategory.NETWORK,
    description="SSL 인증서 검증 없이 네트워크 연결 수립.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["verify=False", "ssl._create_unverified_context", "rejectUnauthorized: false"],
    mitre_ttps=["T1573"],
))
_add(MaliciousIndicator(
    code="NET-010",
    name="Unencrypted Communication",
    category=IndicatorCategory.NETWORK,
    description="암호화되지 않은 HTTP 로 원격 서버와 통신.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.DATA_TRANSMISSION],
    detection_hints=["http://", "raw socket"],
    mitre_ttps=["T1071.001"],
))


# ─── DEF: Defense Evasion (6) ─────────────────────
_add(MaliciousIndicator(
    code="DEF-001",
    name="ASCII Art Deception",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="무해해 보이는 ASCII 아트 뒤에 악성 코드 임베드.",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.ENCODING],
    detection_hints=["unusually large multi-line string in setup.py / __init__.py"],
    mitre_ttps=["T1027"],
))
_add(MaliciousIndicator(
    code="DEF-002",
    name="Computational Obfuscation",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="비트연산/문자열 연산으로 데이터 조작 (런타임 복원).",
    severity=Severity.MEDIUM,
    related_dimensions=[AttackDimension.ENCODING],
    detection_hints=["chr(int^int)", "ord arithmetic", "string concat at runtime"],
    mitre_ttps=["T1027"],
))
_add(MaliciousIndicator(
    code="DEF-003",
    name="Encoding-Based Obfuscation",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="Base64 / hex 등 인코딩으로 페이로드 변환.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.ENCODING],
    detection_hints=["base64.b64decode", "bytes.fromhex", "atob"],
    mitre_ttps=["T1027.005", "T1140"],
))
_add(MaliciousIndicator(
    code="DEF-004",
    name="Encryption-Based Obfuscation",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="중요 코드 부분 암호화로 악성 의도 은닉.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.ENCODING],
    detection_hints=["AES.new", "Fernet(", "RC4", "XOR with key"],
    mitre_ttps=["T1027"],
))
_add(MaliciousIndicator(
    code="DEF-005",
    name="Embedded String Payload",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="문자열 안에 악성 코드를 임베드해 런타임에 실행.",
    severity=Severity.HIGH,
    related_dimensions=[AttackDimension.ENCODING, AttackDimension.PAYLOAD_EXECUTION],
    detection_hints=["exec(string_var)", "Function(string)", "eval(longstring)"],
    mitre_ttps=["T1027"],
))
_add(MaliciousIndicator(
    code="DEF-006",
    name="Error Suppression",
    category=IndicatorCategory.DEFENSE_EVASION,
    description="에러 메시지 의도적 억제로 비정상 동작 은닉.",
    severity=Severity.LOW,
    related_dimensions=[],
    detection_hints=["try: ... except: pass", "2>/dev/null", "stderr=subprocess.DEVNULL"],
    mitre_ttps=["T1564"],
))


# ─── MET: Metadata Manipulation (6) ───────────────
_add(MaliciousIndicator(
    code="MET-001",
    name="Suspicious Author Identity",
    category=IndicatorCategory.METADATA,
    description="placeholder 이름 또는 일회용 이메일로 저자 정보 위조.",
    severity=Severity.MEDIUM,
    related_dimensions=[],
    detection_hints=["author='test'", "throwaway email", "10minutemail"],
    mitre_ttps=["T1195.001"],
))
_add(MaliciousIndicator(
    code="MET-002",
    name="Combosquatting",
    category=IndicatorCategory.METADATA,
    description="유명 라이브러리 이름에 단어/접두사를 결합한 패키지명.",
    severity=Severity.MEDIUM,
    related_dimensions=[],
    detection_hints=["popular_name + suffix/prefix"],
    mitre_ttps=["T1195.001"],
))
_add(MaliciousIndicator(
    code="MET-003",
    name="Suspicious Dependency",
    category=IndicatorCategory.METADATA,
    description="패키지 목적과 일치하지 않는 비정상적 의존성 선언.",
    severity=Severity.MEDIUM,
    related_dimensions=[],
    detection_hints=["json parser depends on subprocess libs", "inconsistent deps"],
    mitre_ttps=["T1195.001"],
))
_add(MaliciousIndicator(
    code="MET-004",
    name="Description Anomaly",
    category=IndicatorCategory.METADATA,
    description="무의미 텍스트, 키워드 스터핑, 랜덤 문자가 포함된 설명.",
    severity=Severity.LOW,
    related_dimensions=[],
    detection_hints=["random keyword stuffing", "lorem ipsum"],
    mitre_ttps=["T1195.001"],
))
_add(MaliciousIndicator(
    code="MET-005",
    name="Decoy Functionality",
    category=IndicatorCategory.METADATA,
    description="양성 목적으로 위장된 기능으로 악성 행위 은폐.",
    severity=Severity.MEDIUM,
    related_dimensions=[],
    detection_hints=["stated purpose vs actual code mismatch"],
    mitre_ttps=["T1195.001"],
))
_add(MaliciousIndicator(
    code="MET-006",
    name="Metadata Typosquatting",
    category=IndicatorCategory.METADATA,
    description="유명 라이브러리와 매우 유사한 이름 선택 (편집거리 1~2).",
    severity=Severity.HIGH,
    related_dimensions=[],
    detection_hints=["edit_distance(name, popular) <= 2"],
    mitre_ttps=["T1195.001"],
))


# ─── DOW: Downloader pattern (Multi-stage 공격 #Z2) ─────────────────
# Stage-1 downloader 자체는 단순하지만, "fetch + exec/eval/run" 콤보는
# multi-stage 공격 의 거의 정의적 패턴. 이 콤보가 단일 파일에 등장 → HIGH.
_add(MaliciousIndicator(
    code="DOW-001",
    name="Single-file Downloader-Exec Pattern",
    category=IndicatorCategory.EXECUTION_STAGE,
    description=(
        "한 파일 내에서 HTTP/fetch 호출 결과를 그대로 exec/eval/run 으로 "
        "넘기는 다단계 downloader 패턴. Stage-2 페이로드를 동적으로 가져와 "
        "실행 — heavy obfuscation 우회의 전형."
    ),
    severity=Severity.HIGH,
    related_dimensions=[
        AttackDimension.DATA_TRANSMISSION,
        AttackDimension.PAYLOAD_EXECUTION,
    ],
    detection_hints=[
        "requests.get + exec/eval/compile",
        "urllib.request.urlopen + exec",
        "fetch/axios + Function/eval",
        "child_process.exec on fetch response",
    ],
    mitre_ttps=["T1059", "T1105"],
))
_add(MaliciousIndicator(
    code="DOW-002",
    name="Write-then-Exec Downloader",
    category=IndicatorCategory.EXECUTION_STAGE,
    description=(
        "fetch → fs.writeFile / open(...).write → 그 파일을 즉시 execute. "
        "DOW-001 보다 1 단계 더 — 파일 시스템 인디케이터 남김."
    ),
    severity=Severity.HIGH,
    related_dimensions=[
        AttackDimension.DATA_TRANSMISSION,
        AttackDimension.PAYLOAD_EXECUTION,
    ],
    detection_hints=[
        "open(..., 'wb').write + subprocess.run / os.system",
        "fs.writeFileSync + child_process.exec",
    ],
    mitre_ttps=["T1105", "T1059"],
))


# ─────────────────── 조회 헬퍼 ───────────────────

def get(code: str) -> MaliciousIndicator | None:
    return INDICATORS.get(code)


def by_category(category: IndicatorCategory) -> list[MaliciousIndicator]:
    return [i for i in INDICATORS.values() if i.category == category]


def all_indicators() -> list[MaliciousIndicator]:
    return list(INDICATORS.values())


def by_dimension(dim: AttackDimension) -> list[MaliciousIndicator]:
    return [i for i in INDICATORS.values() if dim in i.related_dimensions]


def by_severity(sev: Severity) -> list[MaliciousIndicator]:
    return [i for i in INDICATORS.values() if i.severity == sev]


# ─────────────────── 통계 / 자체 검증 ───────────────────

def stats() -> dict:
    from collections import Counter
    cat_count = Counter(i.category.value for i in INDICATORS.values())
    sev_count = Counter(i.severity.value for i in INDICATORS.values())
    return {
        "total": len(INDICATORS),
        "by_category": dict(cat_count),
        "by_severity": dict(sev_count),
    }


# ─────────────────── CLI ───────────────────

if __name__ == "__main__":
    import json
    s = stats()
    print(json.dumps(s, indent=2, ensure_ascii=False))

    # 카테고리별 지표 코드 출력
    for cat in IndicatorCategory:
        codes = [i.code for i in by_category(cat)]
        print(f"\n[{cat.value}] ({len(codes)}): {codes}")

    # 무결성 검증
    expected_per_cat = {
        IndicatorCategory.EXECUTION_STAGE: 3,
        IndicatorCategory.EXECUTION_MECHANISM: 8,
        IndicatorCategory.EXFILTRATION: 5,
        IndicatorCategory.SYSTEM_IMPACT: 9,
        IndicatorCategory.NETWORK: 10,
        IndicatorCategory.DEFENSE_EVASION: 6,
        IndicatorCategory.METADATA: 6,
    }
    for cat, n in expected_per_cat.items():
        actual = len(by_category(cat))
        status = "OK" if actual == n else "MISMATCH"
        print(f"  {cat.value}: {actual}/{n}  [{status}]")
    assert len(INDICATORS) == 47, f"expected 47, got {len(INDICATORS)}"
    print("\nTotal 47 indicators: OK")
