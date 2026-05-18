FROM python:3.11-slim

# 시스템 의존성 (SQLCipher 빌드, tree-sitter 빌드, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libsqlcipher-dev \
    libssl-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# V2 엔진의 의존성을 미리 설치 (pyproject.toml 기준)
# 이미지 빌드 시점에 한 번만 — 빠른 컨테이너 재시작용
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        sqlcipher3 \
        sentence-transformers \
        httpx \
        anthropic \
        openai \
        rich \
        fastapi \
        uvicorn[standard] \
        pydantic \
        tomli \
        tree-sitter \
        tree-sitter-javascript \
        pefile \
        pyelftools \
        rapidfuzz

# 어댑터 코드 (개발 중엔 볼륨으로 덮어씀)
COPY adapter /app/adapter

# V2 엔진은 볼륨으로 /opt/pkgsentinel/src 에 마운트됨
# PYTHONPATH 설정으로 pkgsentinel import 가능하게
ENV PYTHONPATH=/opt/pkgsentinel/src:/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8001

CMD ["uvicorn", "adapter.main:app", \
     "--host", "0.0.0.0", "--port", "8001", "--reload"]