"""
무결성 검증기 — strict / paranoid / (legacy) fast 3 모드.

본 모듈의 차별화 포인트:
  - **registry 메타 신뢰 0**: PyPI/npm 의 dist.shasum 같은 필드를 비교용으로 쓰지 않음.
    archive 를 직접 다운로드해 hashlib 으로 sha256 을 자체 계산.
  - **strict 가 default**: 매 캐시 조회마다 sha256 검증. 시간 비용 있어도 수용.
  - **paranoid 추가 검증**: 파일별 sha256 → Merkle tree → root, 그리고 row HMAC.

논리적 비교:

  fast      HEAD 메타 (ETag/Content-Length) 비교만. *권장 안 함*, diagnostic 용.
  strict    archive 다운로드 → sha256 계산 → 캐시값과 비교.
            registry 인프라 침해 시나리오 대응.
  paranoid  strict + 파일별 sha256 → Merkle root + row HMAC.
            로컬 메모리/저장소 변조 + sub-file 변조 추적까지.

참조:
  - RFC 6962 (Merkle tree, Certificate Transparency)
  - SLSA v1.0: provenance integrity 강도 단계화
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


CHUNK_SIZE = 65536  # 64 KiB
DEFAULT_TIMEOUT = 30


class IntegrityMode(str, Enum):
    FAST = "fast"          # HEAD 메타만. 비추.
    STRICT = "strict"      # archive sha256 자체 계산. **default**.
    PARANOID = "paranoid"  # strict + Merkle + HMAC


# ─────────────── Fingerprint ───────────────

@dataclass
class Fingerprint:
    """archive 의 무결성 지문.

    mode 별로 채우는 필드가 다름:
      fast      : etag, content_length, last_modified
      strict    : archive_sha256
      paranoid  : archive_sha256 + file_hashes + merkle_root
    """
    mode: IntegrityMode
    archive_url: str

    # fast
    etag: Optional[str] = None
    content_length: Optional[int] = None
    last_modified: Optional[str] = None

    # strict
    archive_sha256: Optional[str] = None
    archive_size: Optional[int] = None

    # paranoid
    file_hashes: dict[str, str] = field(default_factory=dict)
    merkle_root: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "url": self.archive_url,
            "etag": self.etag,
            "content_length": self.content_length,
            "last_modified": self.last_modified,
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
            "file_hash_count": len(self.file_hashes),
            "merkle_root": self.merkle_root,
        }


# ─────────────── 다운로드 + 해시 ───────────────

def _http_get_stream(url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[bytes, dict]:
    """archive 전체 + 응답 헤더 반환."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "ai-slopsq/2.0 integrity"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read()
        return body, headers


def _http_head(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    req = urllib.request.Request(
        url, method="HEAD",
        headers={"User-Agent": "ai-slopsq/2.0 integrity"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {k.lower(): v for k, v in resp.headers.items()}


def _hash_bytes(data: bytes) -> tuple[str, int]:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest(), len(data)


# ─────────────── Merkle tree ───────────────

def _merkle_root(leaves: list[str]) -> str:
    """RFC 6962 스타일 binary Merkle tree.

    leaves: hex-encoded sha256 strings (각 leaf 는 sha256(file_content))
    leaf node hash = sha256(0x00 || leaf_hash_bytes)
    inner node    = sha256(0x01 || left || right)
    홀수 수 노드 시 마지막 leaf 를 그대로 promote.
    """
    if not leaves:
        return ""
    if len(leaves) == 1:
        return leaves[0]

    # leaf 단계: 각 leaf 를 0x00 prefix 로 한 번 더 해시
    nodes = [
        hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest()
        for h in leaves
    ]
    # 트리 재귀
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                nxt.append(
                    hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest()
                )
            else:
                # 홀수 promote
                nxt.append(nodes[i])
        nodes = nxt
    return nodes[0].hex()


# ─────────────── archive 내부 파일별 hash ───────────────

def _file_hashes_from_archive(data: bytes, archive_url: str) -> dict[str, str]:
    """archive 내부 각 파일의 sha256 을 {path: sha256} 으로 반환.

    .tar.gz / .tgz / .whl / .zip 지원. 그 외엔 빈 dict.
    경로 정렬 후 반환 (Merkle 입력 결정성 확보).
    """
    fh: dict[str, str] = {}
    lower = archive_url.lower()

    try:
        if lower.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    extract = tf.extractfile(m)
                    if extract is None:
                        continue
                    content = extract.read()
                    fh[m.name] = hashlib.sha256(content).hexdigest()
        elif lower.endswith(".tar"):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    extract = tf.extractfile(m)
                    if extract is None:
                        continue
                    fh[m.name] = hashlib.sha256(extract.read()).hexdigest()
        elif lower.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for n in zf.namelist():
                    if n.endswith("/"):  # directory
                        continue
                    fh[n] = hashlib.sha256(zf.read(n)).hexdigest()
    except Exception:
        # archive 손상 — 빈 dict 반환 (호출자가 decide)
        return {}

    # 결정적 정렬
    return dict(sorted(fh.items()))


# ─────────────── Fingerprint 생성 ───────────────

class IntegrityChecker:
    def __init__(self, mode: IntegrityMode = IntegrityMode.STRICT):
        self.mode = mode

    # public
    def fingerprint(self, archive_url: str) -> Fingerprint:
        if self.mode == IntegrityMode.FAST:
            return self._fingerprint_fast(archive_url)
        if self.mode == IntegrityMode.STRICT:
            return self._fingerprint_strict(archive_url)
        if self.mode == IntegrityMode.PARANOID:
            return self._fingerprint_paranoid(archive_url)
        raise ValueError(f"unknown mode: {self.mode}")

    def matches(self, cached: Fingerprint, fresh: Fingerprint) -> tuple[bool, str]:
        """캐시 hit 가능 여부 + 사유.

        모드 mismatch (예: 캐시는 strict, 현재 paranoid) 시:
          - 캐시 모드가 더 약함 → 무효 (재분석)
          - 캐시 모드가 더 강함 → 현재 모드 기준으로만 검증
        """
        rank = {
            IntegrityMode.FAST: 0,
            IntegrityMode.STRICT: 1,
            IntegrityMode.PARANOID: 2,
        }
        cached_rank = rank.get(IntegrityMode(cached.mode), 0)
        fresh_rank = rank.get(IntegrityMode(fresh.mode), 0)
        if cached_rank < fresh_rank:
            return False, (
                f"cache mode '{cached.mode}' is weaker than current "
                f"'{fresh.mode}' -> invalidate"
            )

        # fresh.mode 기준 비교 (cached 가 더 강하면 strict 부분만 체크)
        if fresh.mode == IntegrityMode.FAST.value:
            if (cached.etag and cached.etag == fresh.etag and
                cached.content_length == fresh.content_length):
                return True, "fast: ETag + Content-Length match"
            return False, "fast: HEAD meta mismatch"

        # strict / paranoid 둘 다 archive_sha256 비교가 첫 필수 조건
        if not cached.archive_sha256 or not fresh.archive_sha256:
            return False, "missing archive_sha256"
        if cached.archive_sha256 != fresh.archive_sha256:
            return False, (
                f"archive sha256 changed "
                f"({cached.archive_sha256[:12]}.. → {fresh.archive_sha256[:12]}..)"
            )

        if fresh.mode == IntegrityMode.PARANOID.value:
            if not cached.merkle_root or not fresh.merkle_root:
                return False, "paranoid: missing merkle_root"
            if cached.merkle_root != fresh.merkle_root:
                return False, (
                    f"paranoid: merkle root changed "
                    f"({cached.merkle_root[:12]}.. → {fresh.merkle_root[:12]}..)"
                )

        return True, f"{fresh.mode}: integrity match"

    # internal
    def _fingerprint_fast(self, url: str) -> Fingerprint:
        try:
            h = _http_head(url)
        except Exception as e:
            return Fingerprint(mode=IntegrityMode.FAST, archive_url=url)
        cl = h.get("content-length")
        return Fingerprint(
            mode=IntegrityMode.FAST,
            archive_url=url,
            etag=h.get("etag"),
            content_length=int(cl) if cl and cl.isdigit() else None,
            last_modified=h.get("last-modified"),
        )

    def _fingerprint_strict(self, url: str) -> Fingerprint:
        body, headers = _http_get_stream(url)
        digest, size = _hash_bytes(body)
        return Fingerprint(
            mode=IntegrityMode.STRICT,
            archive_url=url,
            etag=headers.get("etag"),
            content_length=size,
            last_modified=headers.get("last-modified"),
            archive_sha256=digest,
            archive_size=size,
        )

    def _fingerprint_paranoid(self, url: str) -> Fingerprint:
        body, headers = _http_get_stream(url)
        digest, size = _hash_bytes(body)
        file_hashes = _file_hashes_from_archive(body, url)
        merkle = _merkle_root(list(file_hashes.values()))
        return Fingerprint(
            mode=IntegrityMode.PARANOID,
            archive_url=url,
            etag=headers.get("etag"),
            content_length=size,
            last_modified=headers.get("last-modified"),
            archive_sha256=digest,
            archive_size=size,
            file_hashes=file_hashes,
            merkle_root=merkle,
        )


# ─────────────── Row HMAC (paranoid only) ───────────────

class RowHMAC:
    """analyses 행 한 건의 HMAC-SHA256.

    DB 가 SQLCipher 로 디스크 변조는 막지만,
    공격자가 더 strong (root + memory patch) 하면 sqlite buffer 를
    직접 패치할 수도 있다. row_hmac 컬럼이 있으면 cache get 시
    재계산 → mismatch → invalidate 로 잡는다.

    HMAC 키는 별도 (DB 패스프레이즈 와는 다름):
      - 환경변수 AISLOP_ROW_HMAC_KEY 또는
      - master_key.resolve_passphrase() 의 sha256 derivation 으로 자동 생성
    """

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("HMAC key must be >= 32 bytes")
        self._key = key

    @classmethod
    def from_passphrase(cls, passphrase: str) -> "RowHMAC":
        # HKDF 가 정석이지만 단순화: sha256(passphrase || "row-hmac-v1")
        derived = hashlib.sha256(
            passphrase.encode("utf-8") + b"|row-hmac-v1"
        ).digest()
        return cls(derived)

    def compute(self, row: dict) -> str:
        """행 dict 를 결정적 JSON 으로 직렬화 후 HMAC."""
        # row_hmac 자체는 제외하고 계산
        clean = {k: row[k] for k in sorted(row.keys()) if k != "row_hmac"}
        body = json.dumps(clean, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()

    def verify(self, row: dict, expected_hmac: str) -> bool:
        if not expected_hmac:
            return False
        actual = self.compute(row)
        return hmac.compare_digest(actual, expected_hmac)


# ─────────────── CLI 자체 검증 ───────────────

if __name__ == "__main__":
    import sys

    # 외부 호출이 없는 자체 검증: 작은 byte stream 으로 강도별 동작 보여줌
    print("== Merkle root self-check ==")
    leaves = [hashlib.sha256(f"file-{i}".encode()).hexdigest() for i in range(5)]
    root = _merkle_root(leaves)
    print(f"  5 leaves -> root = {root[:24]}..")
    # 같은 leaves -> 같은 root
    root2 = _merkle_root(leaves)
    assert root == root2
    # 한 leaf 변경 -> root 달라짐
    leaves2 = leaves.copy()
    leaves2[2] = hashlib.sha256(b"tampered").hexdigest()
    root3 = _merkle_root(leaves2)
    assert root != root3
    print(f"  tamper detection: OK (root changes)")

    print("\n== Row HMAC self-check ==")
    rh = RowHMAC.from_passphrase("dev-test-passphrase-9j2k4l8m")
    row = {
        "package": "evil-pkg",
        "ecosystem": "PyPI",
        "version": "1.0.0",
        "verdict": "MALICIOUS",
        "archive_sha256": "abcd" * 16,
    }
    sig = rh.compute(row)
    print(f"  sig = {sig[:24]}..")
    assert rh.verify(row, sig)
    # 행 변조
    row["verdict"] = "CLEAN"
    assert not rh.verify(row, sig)
    print(f"  tamper detection: OK (verify fails)")

    print("\n== Mode comparison logic ==")
    chk = IntegrityChecker(IntegrityMode.STRICT)
    cached = Fingerprint(
        mode=IntegrityMode.STRICT, archive_url="x",
        archive_sha256="a" * 64,
    )
    fresh_same = Fingerprint(
        mode=IntegrityMode.STRICT, archive_url="x",
        archive_sha256="a" * 64,
    )
    fresh_diff = Fingerprint(
        mode=IntegrityMode.STRICT, archive_url="x",
        archive_sha256="b" * 64,
    )
    ok, why = chk.matches(cached, fresh_same)
    print(f"  same sha256:    hit={ok}, {why}")
    ok, why = chk.matches(cached, fresh_diff)
    print(f"  diff sha256:    hit={ok}, {why}")

    # 캐시 약함 → 무효
    cached_fast = Fingerprint(mode=IntegrityMode.FAST, archive_url="x")
    chk_strict = IntegrityChecker(IntegrityMode.STRICT)
    ok, why = chk_strict.matches(cached_fast, fresh_same)
    print(f"  weaker cache:   hit={ok}, {why}")

    print("\nALL OK")
