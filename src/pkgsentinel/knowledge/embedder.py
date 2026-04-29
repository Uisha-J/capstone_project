"""
TTPEntry 임베딩 + 코사인 유사도 검색.

pgvector / Qdrant 없이 메모리 상에서 NumPy 기반으로 동작.
로컬 개발 및 프로토타입에 충분한 규모 (~1000 TTP).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from ..schema import TTPEntry

# 경량 모델 (~80MB, 384차원)
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model: SentenceTransformer | None = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        print(f"[embedder] loading model: {MODEL_NAME}")
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def _ttp_to_text(ttp: TTPEntry) -> str:
    """TTP를 검색용 텍스트로 변환."""
    parts = [ttp.ttp_name, ttp.description]
    if ttp.detection_hints:
        parts.extend(ttp.detection_hints)
    return " ".join(parts).strip()


def embed_ttps(entries: list[TTPEntry]) -> list[TTPEntry]:
    """각 TTPEntry에 embedding 필드 채움."""
    model = get_model()
    texts = [_ttp_to_text(e) for e in entries]
    print(f"[embedder] embedding {len(texts)} entries")
    vectors = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    for e, v in zip(entries, vectors, strict=False):
        e.embedding = v.tolist()
    return entries


def save_with_embeddings(entries: list[TTPEntry], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([e.to_dict() for e in entries], f, ensure_ascii=False)
    print(f"[embedder] saved {len(entries)} entries (with embeddings) → {path}")


# ─────────────── 검색 ───────────────

class TTPIndex:
    """메모리 상의 코사인 유사도 검색기."""

    def __init__(self, entries: list[TTPEntry]):
        self.entries = [e for e in entries if e.embedding is not None]
        self.matrix = np.array([e.embedding for e in self.entries], dtype=np.float32)
        print(f"[TTPIndex] loaded {len(self.entries)} entries, dim={self.matrix.shape[1]}")

    def query_text(self, text: str, top_k: int = 5) -> list[tuple[TTPEntry, float]]:
        model = get_model()
        q = model.encode([text], normalize_embeddings=True)[0]
        return self._search(q, top_k)

    def query_vector(self, vector: np.ndarray, top_k: int = 5) -> list[tuple[TTPEntry, float]]:
        return self._search(vector, top_k)

    def _search(self, q: np.ndarray, top_k: int) -> list[tuple[TTPEntry, float]]:
        # 이미 L2 정규화되어 있으므로 dot product = cosine similarity
        sims = self.matrix @ q
        idx = np.argsort(-sims)[:top_k]
        return [(self.entries[i], float(sims[i])) for i in idx]


# ─────────────── CLI 진입점 ───────────────

if __name__ == "__main__":
    from .mitre_attack import load_cached

    cache_dir = Path(__file__).parent / "cache"
    raw_path = cache_dir / "mitre_attack.json"
    emb_path = cache_dir / "mitre_attack_embedded.json"

    print("[1/3] loading raw TTP entries...")
    entries = load_cached(raw_path)

    print("[2/3] computing embeddings...")
    entries = embed_ttps(entries)
    save_with_embeddings(entries, emb_path)

    print("[3/3] running sample queries...")
    index = TTPIndex(entries)

    queries = [
        "base64 decode then exec payload",
        "read environment variables and send via http post",
        "encrypt files for ransom",
        "spawn shell with subprocess",
        "curl download and bash execute",
    ]
    for q in queries:
        print(f"\nQ: {q}")
        for ttp, sim in index.query_text(q, top_k=3):
            print(f"  {sim:.3f}  {ttp.ttp_id}  {ttp.ttp_name}")
