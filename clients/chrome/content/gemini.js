/**
 * gemini.js — gemini.google.com 전용
 *
 * Gemini DOM 특성:
 * - 코드블록: message-content pre code, .code-block pre code
 * - 언어 레이블: 코드블록 헤더에 "Python" 텍스트
 * - 스트리밍 중 DOM 요소를 새로 만들어 교체함 → 내용 기반 중복 방지
 * - 삽입 위치: pre.insertAdjacentElement("afterend")
 */

// ── 셀렉터 ────────────────────────────────────────────────────────────────────
const SELECTORS = [
  "message-content pre code",
  ".code-block pre code",
  "pre code",
].join(", ");

// ── 언어 감지 ─────────────────────────────────────────────────────────────────
function guessFilename(codeEl) {
  // 클래스명에서 언어 추출
  const classes = [...(codeEl.classList || []), ...(codeEl.parentElement?.classList || [])];
  for (const cls of classes) {
    const lang = cls.replace(/^(language-|lang-)/, "").toLowerCase();
    if (lang === "python")                       return "script.py";
    if (lang === "javascript" || lang === "js")  return "script.js";
    if (lang === "typescript" || lang === "ts")  return "script.ts";
    if (lang === "json")                         return "package.json";
  }

  // Gemini 코드블록 헤더 텍스트 ("Python", "JavaScript" 등)
  const header =
    codeEl.closest(".code-block, pre")
      ?.previousElementSibling?.textContent?.trim()?.toLowerCase() || "";
  if (header.includes("python"))     return "script.py";
  if (header.includes("javascript")) return "script.js";
  if (header.includes("typescript")) return "script.ts";
  if (header.includes("json"))       return "package.json";

  // 코드 내용으로 추측
  const code = codeEl.textContent || "";
  if (/^\s*(import |from .+ import|def |class )/.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                  return "script.js";
  if (/"dependencies"\s*:/.test(code))                        return "package.json";
  return "script.py";
}

// ── 패널 삽입 ─────────────────────────────────────────────────────────────────
function insertAfterCode(codeEl, newEl) {
  const pre = codeEl.closest("pre");
  if (pre) {
    try { pre.insertAdjacentElement("afterend", newEl); return true; } catch {}
  }
  let el = codeEl;
  for (let i = 0; i < 8; i++) {
    const p = el.parentElement;
    if (!p || p === document.body) break;
    const d = window.getComputedStyle(p).display;
    if (d === "block" || d === "flex" || d === "grid") {
      try { p.insertAdjacentElement("afterend", newEl); return true; } catch {}
    }
    el = p;
  }
  return false;
}

// ── 중복 방지 ─────────────────────────────────────────────────────────────────
// Gemini는 스트리밍 중 DOM을 새로 만들므로 내용 기반으로 추적
let processedKeys = new Set();

function getKey(text) {
  return `${text.length}::${text.slice(0, 60)}::${text.slice(-60)}`;
}

// ── 코드블록 스캔 ─────────────────────────────────────────────────────────────
function scanCodeBlocks() {
  document.querySelectorAll(SELECTORS).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 응답 단위 dedup (Gemini message-content)
    const msg = el.closest("message-content");
    if (msg && msg.hasAttribute("data-slop-code-scanned")) {
      el.setAttribute("data-slop-scanned", "1");
      return;
    }
    const text = (el.textContent || "").trim();
    if (text.length < 80) return;
    const hasImport = /^\s*(import |from .+ import)/m.test(text)
      || /require\(|"dependencies"/.test(text);
    if (!hasImport) return;
    el.setAttribute("data-slop-scanned", "1");
    if (msg) msg.setAttribute("data-slop-code-scanned", "1");
    const filename = guessFilename(el);
    analyzeAndRender(text, filename, (newEl) => insertAfterCode(el, newEl));
  });
}

// ── MutationObserver ──────────────────────────────────────────────────────────
// Gemini 스트리밍이 완전히 끝난 뒤 스캔하도록 debounce 1500ms
const observer = new MutationObserver(() => {
  clearTimeout(observer._timer);
  observer._timer = setTimeout(() => { scanCodeBlocks(); scanResponseText(); }, 1500);
});

// ── 시작 ──────────────────────────────────────────────────────────────────────
(async () => {
  const serverUp = await checkApiServer();
  console.log(`[Slop Detector] 시작 — 사이트: gemini, API: ${serverUp ? "✅ 연결됨" : "❌ 오프라인"}`);
  if (!serverUp) return;

  watchNavigation(() => {
    processedKeys = new Set();
    setTimeout(scanCodeBlocks, 1000);
  });

  scanCodeBlocks();
  scanResponseText();
  observer.observe(document.body, { childList: true, subtree: true });
})();

// ── 텍스트 응답 스캔 (pip/npm install 패턴) ───────────────────────────────────
const processedTextKeys = new Set();

function scanResponseText() {
  document.querySelectorAll("message-content").forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 코드블록 스캔이 이미 처리한 응답이면 텍스트 스캔 스킵 (패널 중복 방지)
    if (el.hasAttribute("data-slop-code-scanned")) return;
    const text = el.innerText || "";
    if (text.length < 20) return;

    // 1단계: pip/npm install 패턴 (고신뢰)
    const installPackages = extractPackagesFromText(text);

    // 2단계: 자연어 감지 — 백틱, import 패턴, 인기 패키지 매칭
    const nlpPackages = typeof extractPackagesFromNaturalText === "function"
      ? extractPackagesFromNaturalText(text)
      : [];

    // 합집합 (중복 제거)
    const allPackages = [...new Set([...installPackages, ...nlpPackages])];

    // 코드블록에서 이미 분석된 패키지 제외
    const newPackages = allPackages.filter(p => {
      return ![...processedKeys].some(k => k.includes(p));
    });
    if (!newPackages.length) return;

    // DOM에 이미 텍스트 패널 있으면 스킵
    if (el.parentElement?.querySelector("[data-slop-text-panel]")) return;

    el.setAttribute("data-slop-scanned", "1");
    console.log(`[Slop Detector] Gemini 패키지 감지:`, newPackages);

    analyzePackagesFromText(newPackages, (newEl) => {
      newEl.setAttribute("data-slop-text-panel", "1");
      const existingPanel = el.nextElementSibling?.hasAttribute("data-slop-panel")
        ? el.nextElementSibling : null;
      const insertTarget = existingPanel || el;
      try { insertTarget.insertAdjacentElement("afterend", newEl); return true; } catch {}
      return false;
    });
  });
}
