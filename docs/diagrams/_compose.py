"""
시스템 다이어그램 + 기술 스택 텍스트 합성기.

사용자 capstone 발표 보드 스타일 (위쪽 좌측 정렬 텍스트 블록 + 아래쪽 다이어그램)
을 mermaid 한계 우회로 PIL 합성.

입력: A_system_simple.png
출력: C_system_with_stack.png  (위쪽 텍스트 헤더 추가)
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "A_system_simple.png"
OUT = HERE / "C_system_with_stack.png"

# 기술 스택 항목 (key, value 리스트)
STACK = [
    ("개발 도구", "VS Code · Git / GitHub · npm (mermaid-cli)"),
    ("개발 언어", "Python 3.11+ · JavaScript (tree-sitter) · Markdown / mermaid"),
    ("주요 기술", "SQLCipher (AES-256) · Anthropic Claude API · sentence-transformers · AST · pytest · ruff · pip-audit · xhtml2pdf"),
    ("표준 / 피드", "MITRE ATT&CK / ATLAS · OWASP LLM Top 10 · STIX 2.1 / TAXII · CycloneDX VEX · OSV / GHSA · urlhaus / Feodo"),
    ("인프라 / 출력", "systemd unit · GitHub Actions CI (Ubuntu / Windows × Py 3.11 / 3.12) · Falco rules / Tetragon TracingPolicy"),
]

# 폰트 — Windows 한국어 기본
FONT_PATH_BOLD = "C:/Windows/Fonts/malgunbd.ttf"
FONT_PATH_REG = "C:/Windows/Fonts/malgun.ttf"
FONT_KEY = ImageFont.truetype(FONT_PATH_BOLD, 19)
FONT_VAL = ImageFont.truetype(FONT_PATH_REG, 17)

PADDING = 22
KEY_VAL_GAP = 12
ROW_GAP = 6
HEADER_BG = (245, 245, 245)
HEADER_BORDER = (90, 90, 90)
KEY_COLOR = (20, 30, 70)
VAL_COLOR = (40, 40, 40)
KEY_COL_W = 130   # 모든 key 가 이 폭 안에 들어가도록 정렬


def _wrap_value(value: str, font: ImageFont.ImageFont, max_w: int,
                draw: ImageDraw.ImageDraw) -> list[str]:
    """가로 max_w 안에 들어가도록 단어 단위 wrap (· · · 구분자 보존)."""
    parts = value.split(" · ")
    lines: list[str] = []
    cur = ""
    for i, p in enumerate(parts):
        candidate = (cur + " · " + p) if cur else p
        if draw.textlength(candidate, font=font) <= max_w:
            cur = candidate
        else:
            if cur:
                lines.append(cur)
            cur = p
    if cur:
        lines.append(cur)
    return lines


def _measure(sys_w: int, draw_proxy: ImageDraw.ImageDraw) -> tuple[int, list[list[str]]]:
    val_max_w = sys_w - PADDING * 2 - KEY_COL_W - KEY_VAL_GAP
    wrapped = [_wrap_value(v, FONT_VAL, val_max_w, draw_proxy) for _, v in STACK]
    h = PADDING * 2
    for w_lines in wrapped:
        n = len(w_lines)
        h += max(FONT_KEY.size, n * (FONT_VAL.size + 4)) + ROW_GAP * 2
    return h, wrapped


def main():
    sys_img = Image.open(SRC).convert("RGB")
    sys_w, sys_h = sys_img.size

    proxy = Image.new("RGB", (10, 10))
    proxy_draw = ImageDraw.Draw(proxy)
    header_h, wrapped = _measure(sys_w, proxy_draw)

    out = Image.new("RGB", (sys_w, sys_h + header_h), (255, 255, 255))
    draw = ImageDraw.Draw(out)
    draw.rectangle(
        [(0, 0), (sys_w, header_h)],
        fill=HEADER_BG, outline=HEADER_BORDER, width=2,
    )

    y = PADDING
    for (key, _val), w_lines in zip(STACK, wrapped):
        n = len(w_lines)
        row_h = max(FONT_KEY.size, n * (FONT_VAL.size + 4))
        # key (좌측 정렬, 굵게) — 같은 row 의 첫 줄 baseline 에 정렬
        draw.text((PADDING, y), key, font=FONT_KEY, fill=KEY_COLOR)
        # value lines (wrap 처리)
        x_val = PADDING + KEY_COL_W
        # 콜론 prefix
        for i, line in enumerate(w_lines):
            text = (": " + line) if i == 0 else "  " + line
            draw.text((x_val, y + i * (FONT_VAL.size + 4)),
                      text, font=FONT_VAL, fill=VAL_COLOR)
        y += row_h + ROW_GAP * 2

    out.paste(sys_img, (0, header_h))
    out.save(OUT, "PNG", optimize=True)
    print(f"OK: {OUT}  ({sys_w}x{sys_h+header_h})")


if __name__ == "__main__":
    main()
