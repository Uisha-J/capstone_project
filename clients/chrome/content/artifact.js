/**
 * artifact.js — a.claude.ai iframe 전용
 *
 * 코드 추출 → 분석 → 결과를 부모(claude.ai)로 postMessage
 * 패널 표시는 claude.js가 아티팩트 카드 아래에 담당
 */

function guessFilenameFromCode(code) {
  if (/^\s*(import |from .+ import|def |class )/m.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                   return "script.js";
  if (/"dependencies"\s*:/.test(code))                         return "package.json";
  return "script.py";
}

// ── Cloudflare 보호/챌린지 프레임 식별 (아티팩트 아님) ─────────────────────
function _isCloudflareFrame() {
  try {
    const url = location.href || "";
    if (url.includes("cdn-cgi/") || url.includes("challenge-platform")) return true;
    const html = document.documentElement?.outerHTML || "";
    // CF 챌린지의 시그니처
    if (html.includes("__CF$cv$params") || html.includes("Isolated Segment")) return true;
    const bodyText = (document.body?.innerText || "").trim();
    // CF 챌린지는 짧고 콘텐츠 없음
    if (bodyText.length < 200 && /cloudflare|challenge|__cf/i.test(html)) return true;
    return false;
  } catch { return false; }
}

function extractCode() {
  // CF 프레임이면 즉시 종료
  if (_isCloudflareFrame()) {
    console.log("[Slop Detector] CF 보호 프레임 감지 - 스킵");
    return null;
  }

  // 전략 1: token 요소 → 상위 코드 컨테이너
  const tokenEl = document.querySelector("[class*='token']");
  if (tokenEl) {
    let el = tokenEl;
    for (let i = 0; i < 8; i++) {
      el = el.parentElement;
      if (!el) break;
      const cls = el.className || "";
      if (cls.includes("min-w-0") && cls.includes("max-w-full")) {
        const raw = el.innerText || "";
        const lines = raw.split("\n");
        const isNumbered = /^\d+$/.test(lines[0]?.trim());
        const code = isNumbered
          ? lines.filter((_, i) => i % 2 === 1).join("\n")
          : raw;
        if (code.length > 30) {
          console.log(`[Slop Detector] 코드 추출 성공 (token→parent, ${code.length}자)`);
          return code;
        }
      }
    }
  }

  // 전략 2: 다양한 코드 뷰어 셀렉터
  const selectors = [
    ".view-lines",
    ".CodeMirror-code",
    "pre code",
    "pre",
    "[class*='code-block']",
    "[class*='monaco']",
    "[class*='cm-content']",
    "[class*='editor']",
    "[data-language]",
    "code",
  ];
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el) {
      const text = (el.innerText || el.textContent || "").trim();
      if (text.length > 30) {
        console.log(`[Slop Detector] 코드 추출 성공 (${sel}, ${text.length}자)`);
        return text;
      }
    }
  }

  // 전략 3: body에서 코드 패턴 직접 탐색 (최후 수단)
  const bodyText = (document.body?.innerText || "").trim();
  if (bodyText.length > 80) {
    const hasCode = /^\s*(import |from .+ import|def |class |require\(|const |function )/m.test(bodyText);
    if (hasCode) {
      console.log(`[Slop Detector] 코드 추출 성공 (body 전체, ${bodyText.length}자)`);
      return bodyText;
    }
  }

  // 디버그: DOM 구조 출력
  console.log(`[Slop Detector] 코드 추출 실패. DOM 디버그:`);
  console.log(`  token 요소: ${!!tokenEl}`);
  console.log(`  body 길이: ${bodyText.length}`);
  console.log(`  body 미리보기: ${bodyText.slice(0, 200)}`);
  const allEls = document.querySelectorAll("*");
  const classes = new Set();
  allEls.forEach(el => (el.className || "").split(/\s+/).forEach(c => { if (c) classes.add(c); }));
  console.log(`  고유 클래스 (${classes.size}개):`, [...classes].slice(0, 30).join(", "));

  return null;
}

let analyzed = false;

async function runAnalysis() {
  if (analyzed) return;

  const code = extractCode();
  if (!code) return;

  const hasImport = /^\s*(import |from .+ import)/m.test(code)
    || /require\(|"dependencies"/.test(code);
  if (!hasImport) return;

  const filename = guessFilenameFromCode(code);
  analyzed = true;

  console.log(`[Slop Detector] 아티팩트 분석: ${filename} (${code.length}자)`);

  try {
    const result = await callBackground({ type: "PARSE_AND_ANALYZE", filename, code });
    if (!result?.results?.length) return;

    console.log(`[Slop Detector] 아티팩트 완료:`, result.results.map(r => `${r.package}(${r.level})`));

    // 결과를 부모 페이지로 전송 (claude.ai 또는 어떤 부모든)
    const parentOrigin = document.referrer
      ? new URL(document.referrer).origin
      : "https://claude.ai";
    window.parent.postMessage({
      type: "SLOP_ARTIFACT_RESULT",
      results: result.results,
    }, parentOrigin);

  } catch (err) {
    console.error("[Slop Detector] 아티팩트 오류:", err.message);
  }
}

const observer = new MutationObserver(() => {
  clearTimeout(observer._timer);
  observer._timer = setTimeout(runAnalysis, 1000);
});

(async () => {
  // CF 보호 프레임이면 즉시 종료 (불필요한 리소스 낭비 방지)
  if (_isCloudflareFrame()) {
    console.log("[Slop Detector] 아티팩트 iframe - CF 프레임이라 종료");
    return;
  }
  const serverUp = await checkApiServer();
  console.log(`[Slop Detector] 아티팩트 iframe, URL: ${location.host}, API: ${serverUp ? "✅" : "❌"}`);
  if (!serverUp) return;

  setTimeout(runAnalysis, 800);
  observer.observe(document.body, { childList: true, subtree: true });
})();
