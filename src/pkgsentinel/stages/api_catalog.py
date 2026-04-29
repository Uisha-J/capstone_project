"""
4 Attack Dimension × (Python / JavaScript) API 카탈로그.

Cerebro 논문의 16 features + DONAPI의 132 API 를 참고하여
코드 패턴으로 식별 가능한 것만 선별.

각 엔트리는 (fully.qualified.name, AttackDimension) 로 정의.
"""
from __future__ import annotations

from ..schema import AttackDimension

# ───────────────────── Python ─────────────────────

PYTHON_APIS: dict[str, AttackDimension] = {
    # ─── Information Reading ───
    "os.environ.get": AttackDimension.INFORMATION_READING,
    "os.environ.__getitem__": AttackDimension.INFORMATION_READING,
    "os.getenv": AttackDimension.INFORMATION_READING,
    "os.uname": AttackDimension.INFORMATION_READING,
    "platform.uname": AttackDimension.INFORMATION_READING,
    "platform.system": AttackDimension.INFORMATION_READING,
    "platform.node": AttackDimension.INFORMATION_READING,
    "platform.machine": AttackDimension.INFORMATION_READING,
    "platform.platform": AttackDimension.INFORMATION_READING,
    "getpass.getuser": AttackDimension.INFORMATION_READING,
    "socket.gethostname": AttackDimension.INFORMATION_READING,
    "socket.gethostbyname": AttackDimension.INFORMATION_READING,
    "pathlib.Path.home": AttackDimension.INFORMATION_READING,
    "os.path.expanduser": AttackDimension.INFORMATION_READING,
    # 'open', 'io.open' 제외 — 정상 코드에서 너무 빈번 (FP 유발)
    # 파일 읽기 자체는 INFORMATION_READING 이지만, 판정 근거로는 약함
    # 민감 경로 결합(~/.ssh, /etc/passwd 등)은 string_analysis 모듈에서 다룸

    # ─── Encoding / Obfuscation ───
    "base64.b64decode": AttackDimension.ENCODING,
    "base64.b64encode": AttackDimension.ENCODING,
    "base64.b32decode": AttackDimension.ENCODING,
    "base64.a85decode": AttackDimension.ENCODING,
    "base64.urlsafe_b64decode": AttackDimension.ENCODING,
    "codecs.decode": AttackDimension.ENCODING,
    "codecs.encode": AttackDimension.ENCODING,
    "zlib.decompress": AttackDimension.ENCODING,
    "zlib.compress": AttackDimension.ENCODING,
    "gzip.decompress": AttackDimension.ENCODING,
    "bz2.decompress": AttackDimension.ENCODING,
    # pickle.loads / marshal.loads 는 untrusted 입력 시 RCE 동등 — PAYLOAD_EXECUTION 으로 분류
    "marshal.loads": AttackDimension.PAYLOAD_EXECUTION,
    "pickle.loads": AttackDimension.PAYLOAD_EXECUTION,
    # 'compile' 제외 — Python config 파일 (flask/django 설정) 등에서 정당하게 사용
    "bytes.fromhex": AttackDimension.ENCODING,

    # ─── Payload Execution ───
    "exec": AttackDimension.PAYLOAD_EXECUTION,
    "eval": AttackDimension.PAYLOAD_EXECUTION,
    "__import__": AttackDimension.PAYLOAD_EXECUTION,
    "importlib.import_module": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.run": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.Popen": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.call": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.check_call": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.check_output": AttackDimension.PAYLOAD_EXECUTION,
    "subprocess.getoutput": AttackDimension.PAYLOAD_EXECUTION,
    "os.system": AttackDimension.PAYLOAD_EXECUTION,
    "os.popen": AttackDimension.PAYLOAD_EXECUTION,
    "os.execv": AttackDimension.PAYLOAD_EXECUTION,
    "os.execvp": AttackDimension.PAYLOAD_EXECUTION,
    "os.execve": AttackDimension.PAYLOAD_EXECUTION,
    "os.spawnv": AttackDimension.PAYLOAD_EXECUTION,
    "os.fork": AttackDimension.PAYLOAD_EXECUTION,
    "pty.spawn": AttackDimension.PAYLOAD_EXECUTION,
    "ctypes.CDLL": AttackDimension.PAYLOAD_EXECUTION,
    "ctypes.windll": AttackDimension.PAYLOAD_EXECUTION,

    # ─── Data Transmission ───
    "requests.get": AttackDimension.DATA_TRANSMISSION,
    "requests.post": AttackDimension.DATA_TRANSMISSION,
    "requests.put": AttackDimension.DATA_TRANSMISSION,
    "requests.patch": AttackDimension.DATA_TRANSMISSION,
    "requests.request": AttackDimension.DATA_TRANSMISSION,
    "urllib.request.urlopen": AttackDimension.DATA_TRANSMISSION,
    "urllib.request.Request": AttackDimension.DATA_TRANSMISSION,
    "urllib.request.urlretrieve": AttackDimension.DATA_TRANSMISSION,
    "urllib.urlopen": AttackDimension.DATA_TRANSMISSION,     # py2 legacy
    "http.client.HTTPConnection": AttackDimension.DATA_TRANSMISSION,
    "http.client.HTTPSConnection": AttackDimension.DATA_TRANSMISSION,
    "httpx.get": AttackDimension.DATA_TRANSMISSION,
    "httpx.post": AttackDimension.DATA_TRANSMISSION,
    "aiohttp.ClientSession": AttackDimension.DATA_TRANSMISSION,
    "socket.socket": AttackDimension.DATA_TRANSMISSION,
    "socket.create_connection": AttackDimension.DATA_TRANSMISSION,
    "ftplib.FTP": AttackDimension.DATA_TRANSMISSION,
    "smtplib.SMTP": AttackDimension.DATA_TRANSMISSION,
    "telnetlib.Telnet": AttackDimension.DATA_TRANSMISSION,
}


# ───────────────────── JavaScript ─────────────────────

# 주의: JS는 import 패턴이 다양해서 네임스페이스가 유동적.
# 여기서는 Cerebro 스타일로 "식별 가능한 호출 명" 을 단순 나열.
JS_APIS: dict[str, AttackDimension] = {
    # ─── Information Reading ───
    "process.env": AttackDimension.INFORMATION_READING,
    "os.userInfo": AttackDimension.INFORMATION_READING,
    "os.hostname": AttackDimension.INFORMATION_READING,
    "os.homedir": AttackDimension.INFORMATION_READING,
    "os.tmpdir": AttackDimension.INFORMATION_READING,
    "os.platform": AttackDimension.INFORMATION_READING,
    "os.arch": AttackDimension.INFORMATION_READING,
    "os.networkInterfaces": AttackDimension.INFORMATION_READING,
    "fs.readFileSync": AttackDimension.INFORMATION_READING,
    "fs.readFile": AttackDimension.INFORMATION_READING,
    "fs.readdirSync": AttackDimension.INFORMATION_READING,
    "fs.readdir": AttackDimension.INFORMATION_READING,
    "fs.statSync": AttackDimension.INFORMATION_READING,

    # ─── Encoding / Obfuscation ───
    "Buffer.from": AttackDimension.ENCODING,
    "atob": AttackDimension.ENCODING,
    "btoa": AttackDimension.ENCODING,
    "zlib.gunzipSync": AttackDimension.ENCODING,
    "zlib.inflateSync": AttackDimension.ENCODING,
    "zlib.brotliDecompressSync": AttackDimension.ENCODING,

    # ─── Payload Execution ───
    "eval": AttackDimension.PAYLOAD_EXECUTION,
    "Function": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.exec": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.execSync": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.spawn": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.spawnSync": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.execFile": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.execFileSync": AttackDimension.PAYLOAD_EXECUTION,
    "child_process.fork": AttackDimension.PAYLOAD_EXECUTION,
    "vm.runInNewContext": AttackDimension.PAYLOAD_EXECUTION,
    "vm.runInThisContext": AttackDimension.PAYLOAD_EXECUTION,
    "vm.Script": AttackDimension.PAYLOAD_EXECUTION,
    "require": AttackDimension.PAYLOAD_EXECUTION,  # 동적 require (require(variable))

    # ─── Data Transmission ───
    "http.request": AttackDimension.DATA_TRANSMISSION,
    "https.request": AttackDimension.DATA_TRANSMISSION,
    "http.get": AttackDimension.DATA_TRANSMISSION,
    "https.get": AttackDimension.DATA_TRANSMISSION,
    "fetch": AttackDimension.DATA_TRANSMISSION,
    "axios.get": AttackDimension.DATA_TRANSMISSION,
    "axios.post": AttackDimension.DATA_TRANSMISSION,
    "net.Socket": AttackDimension.DATA_TRANSMISSION,
    "net.createConnection": AttackDimension.DATA_TRANSMISSION,
    "dgram.createSocket": AttackDimension.DATA_TRANSMISSION,
    "dns.lookup": AttackDimension.DATA_TRANSMISSION,
    "dns.resolve": AttackDimension.DATA_TRANSMISSION,
    "WebSocket": AttackDimension.DATA_TRANSMISSION,
}


# 접미사 매칭의 앞부분이 반드시 이 리스트에 있는 라이브러리여야 (FP 방지)
_PY_HTTP_LIBS = {
    "requests", "httpx", "aiohttp", "urllib",
    "urllib2", "urllib3", "urlfetch", "httpcore",
}


def lookup_python(name: str) -> AttackDimension | None:
    """정확 일치만 허용. 접미사 매칭은 HTTP 클라이언트 라이브러리에만 제한."""
    if name in PYTHON_APIS:
        return PYTHON_APIS[name]

    # HTTP 메서드의 접미사 매칭만 허용 — 반드시 알려진 HTTP 라이브러리 접두사가 필요
    parts = name.split(".")
    if len(parts) < 2:
        return None
    last = parts[-1]
    first = parts[0]

    # requests.get / httpx.post / session.get 같은 형태에서
    # 맨 앞 네임스페이스가 명시적 HTTP 라이브러리인 경우만 허용.
    # 'session', 'request', 'response' 같은 일반 객체명은 제외 -> FP 방지.
    if first in _PY_HTTP_LIBS and last in ("get", "post", "put", "patch", "request"):
        return AttackDimension.DATA_TRANSMISSION

    return None


def lookup_js(name: str) -> AttackDimension | None:
    """정확 일치만 허용. JS 는 네임스페이스가 유동적이라 접미사 매칭 없음."""
    if name in JS_APIS:
        return JS_APIS[name]
    return None


# ───────────────────── 통계 ─────────────────────

if __name__ == "__main__":
    from collections import Counter
    py_dist = Counter(PYTHON_APIS.values())
    js_dist = Counter(JS_APIS.values())
    print(f"Python APIs: {len(PYTHON_APIS)}")
    for dim, n in py_dist.most_common():
        print(f"  {dim.value}: {n}")
    print(f"\nJavaScript APIs: {len(JS_APIS)}")
    for dim, n in js_dist.most_common():
        print(f"  {dim.value}: {n}")
