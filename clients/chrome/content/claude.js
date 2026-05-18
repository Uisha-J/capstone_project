/**
 * claude.js — claude.ai 전용
 *
 * 케이스 1: 코드블록 (pre code) → scanCodeBlocks()
 * 케이스 2: 아티팩트 뷰어 코드 → scanArtifacts()
 *           top DOM의 [class*='token'] → min-w-0.max-w-full 컨테이너에서 추출
 *           아티팩트 카드 부모(rounded-lg) 다음에 패널 삽입
 */

// ── 언어 감지 ─────────────────────────────────────────────────────────────────
function guessFilename(codeEl) {
  const classes = [...(codeEl.classList || []), ...(codeEl.parentElement?.classList || [])];
  for (const cls of classes) {
    const lang = cls.replace(/^(language-|lang-)/, "").toLowerCase();
    if (lang === "python")                       return "script.py";
    if (lang === "javascript" || lang === "js")  return "script.js";
    if (lang === "typescript" || lang === "ts")  return "script.ts";
    if (lang === "json")                         return "package.json";
  }
  const code = codeEl.textContent || "";
  if (/^\s*(import |from .+ import|def |class )/m.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                   return "script.js";
  if (/"dependencies"\s*:/.test(code))                         return "package.json";
  return "script.py";
}

function guessFilenameFromCode(code) {
  if (/^\s*(import |from .+ import|def |class )/m.test(code)) return "script.py";
  if (/require\(|import .+ from/.test(code))                   return "script.js";
  if (/"dependencies"\s*:/.test(code))                         return "package.json";
  return "script.py";
}

// ── DOM 삽입 ─────────────────────────────────────────────────────────────────
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
let processedKeys = new Set();

function getKey(text) {
  return `${text.length}::${text.slice(0, 60)}::${text.slice(-60)}`;
}

// 아티팩트 분석 상태: 스트리밍 중 debounce + 카드 잠금
let _artifactTimer = null;
let _pendingCard = null;

// ── 케이스 1: 코드블록 스캔 ──────────────────────────────────────────────────
function scanCodeBlocks() {
  document.querySelectorAll("pre code").forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 응답 단위 dedup: 같은 응답에 이미 다른 코드블록이 처리 중이면 스킵
    const msg = el.closest(".font-claude-message, [data-is-streaming], [class*='prose']");
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

// ── 케이스 2: 아티팩트 코드 추출 ─────────────────────────────────────────────
// 추출 결과: { code, container } — container 는 패널 삽입 위치 결정에 사용
function extractArtifactCode() {
  // ── 전략 0: 신규 Claude 아티팩트 UI (2026~) ─────────────────────────
  // 각 코드 줄이 [class*='group/line'] 컨테이너로 마킹됨.
  // 각 line 의 innerText 를 join — 줄 번호는 line 외부 컬럼이라 자연 제외됨.
  const lineEls = document.querySelectorAll("[class*='group/line']");
  if (lineEls.length >= 3) {
    const codes = [...lineEls].map(l => (l.innerText || "").replace(/\n+$/, ""));
    const code = codes.filter(Boolean).join("\n").trim();
    if (code.length >= 80) {
      // 로그 중복 방지: 같은 추출 결과면 로그 출력 안 함
      const logKey = `${lineEls.length}:${code.length}`;
      if (extractArtifactCode._lastLogKey !== logKey) {
        console.log(`[Slop Detector] 신규 UI 코드 추출 (group/line, ${lineEls.length}줄, ${code.length}자)`);
        extractArtifactCode._lastLogKey = logKey;
      }
      const linesParent = lineEls[0].parentElement;
      return { code, container: linesParent };
    }
  }

  // ── 전략 1: 사이드 패널/모달 안의 코드 컨테이너 ───────────────────────
  // Claude 아티팩트 패널의 가능한 컨테이너
  const panelSelectors = [
    "[data-testid='artifact-panel']",
    "[data-testid='artifact-content']",
    "[data-testid*='artifact']",
    "[aria-label*='artifact' i]",
    "[class*='ArtifactPanel']",
    "[class*='artifact-panel']",
    "[class*='ArtifactPreview']",
    "[class*='artifact-preview']",
  ];
  const panelEl = document.querySelector(panelSelectors.join(", "));

  // 패널 안의 코드 후보 셀렉터들 (Monaco / CodeMirror / Prism / 일반)
  const codeSelectors = [
    ".view-lines",            // Monaco editor
    ".cm-content",            // CodeMirror 6
    ".CodeMirror-code",       // CodeMirror 5
    "[class*='token']",       // Prism.js (claude 기본)
    "pre code",
    "pre",
  ];

  function _cleanText(raw) {
    if (!raw) return "";
    const lines = raw.split("\n");
    // 줄번호 + 코드 패턴 (홀수줄=번호) 제거
    const isNumbered = lines.length > 2 && /^\d+$/.test(lines[0]?.trim()) && /^\d+$/.test(lines[2]?.trim());
    return isNumbered ? lines.filter((_, i) => i % 2 === 1).join("\n") : raw;
  }

  // 패널이 있으면 그 안에서 우선 탐색
  const searchRoots = panelEl ? [panelEl, document] : [document];
  for (const root of searchRoots) {
    for (const sel of codeSelectors) {
      const els = root.querySelectorAll(sel);
      for (const el of els) {
        // 채팅 메시지 내부면 스킵 (대화 본문은 scanCodeBlocks 가 처리)
        if (el.closest(".font-claude-message, .prose, [data-message-author-role]")) continue;
        const raw = el.innerText || el.textContent || "";
        const code = _cleanText(raw);
        if (code.length < 80) continue;
        // 토큰 셀렉터인 경우 상위 컨테이너로 확장 (밀도 기반)
        if (sel.includes("token")) {
          let cur = el;
          let best = el;
          for (let i = 0; i < 12; i++) {
            cur = cur.parentElement;
            if (!cur || cur === document.body) break;
            if (cur.closest(".font-claude-message, .prose, [data-message-author-role]")) break;
            const cnt = cur.querySelectorAll("[class*='token']").length;
            if (cnt >= 5 && (cur.innerText || "").length > best.innerText?.length) {
              best = cur;
              const parentTokens = cur.parentElement?.querySelectorAll("[class*='token']").length || 0;
              if (parentTokens > cnt * 3) break;
            }
          }
          const expanded = _cleanText(best.innerText || "");
          if (expanded.length > code.length) {
            return { code: expanded, container: best };
          }
        }
        return { code, container: el };
      }
    }
  }

  return null;
}

// 직전에 처리한 코드 시그니처 (스트리밍 중 같은 코드 재처리 방지)
let _lastArtifactKey = null;

function _artifactKey(code) {
  return `${code.length}::${code.slice(0, 80)}::${code.slice(-40)}`;
}

function scanArtifacts() {
  const found = extractArtifactCode();
  if (!found || !found.code || found.code.length < 80) return;

  const hasImport = /^\s*(import |from .+ import)/m.test(found.code)
    || /require\(|"dependencies"/.test(found.code);
  if (!hasImport) return;

  // 같은 코드 중복 처리 방지
  const key = _artifactKey(found.code);
  if (key === _lastArtifactKey) return;

  // ── 스트리밍 중 debounce ────────────────────────────────────────
  if (_artifactTimer) {
    clearTimeout(_artifactTimer);
    _artifactTimer = setTimeout(() => _analyzeStableArtifact(), 2000);
    return;
  }

  // 카드는 있으면 잠금 (선택적), 없어도 진행
  const cards = [...document.querySelectorAll("[class*='artifact-block'], [class*='artifact-preview'], [class*='ArtifactPreview'], [data-testid*='artifact'], [aria-label*='artifact' i]")];
  _pendingCard = cards.find(c => !c.hasAttribute("data-slop-analyzed")) || null;
  if (_pendingCard) _pendingCard.setAttribute("data-slop-analyzed", "1");

  _artifactTimer = setTimeout(() => _analyzeStableArtifact(), 2000);
}

// 패널을 삽입할 최적 위치 찾기 + 삽입 모드 결정
// 반환: { el, mode } — mode "prepend"/"append"/"after"
//
// 중요: 신규 Claude UI는 React 가 아티팩트 코드 패널 내부 자식을 reconciliation 으로
// 관리하기 때문에, 그 안에 직접 DOM 노드 삽입하면 즉시 제거됨.
// 옛 방식대로 채팅 좌측의 아티팩트 카드 row 다음에 삽입하는 게 stable.
// (채팅 메시지 사이는 React가 안정적으로 list reconciliation)
function _findArtifactInsertionPoint(card, container) {
  // 전략 1 (우선): 채팅 카드 다음 row — React 안전 지대
  if (card) {
    const rowContainer = card.parentElement?.parentElement?.parentElement?.parentElement;
    if (rowContainer) return { el: rowContainer, mode: "after" };
  }
  // 전략 2 (폴백): container 의 stable 조상 찾기
  if (container) {
    let el = container;
    for (let i = 0; i < 10; i++) {
      el = el.parentElement;
      if (!el || el === document.body) break;
      const cls = (el.className || "").toString().toLowerCase();
      // 채팅 메시지 단위로 추정되는 컨테이너
      if (el.matches("[data-testid*='message'], [data-is-streaming]") ||
          cls.includes("conversation") || cls.includes("group/message")) {
        return { el, mode: "after" };
      }
    }
    return { el: container, mode: "after" };
  }
  return null;
}

function _analyzeStableArtifact() {
  _artifactTimer = null;
  const card = _pendingCard;
  _pendingCard = null;

  // 안정화된 최종 코드 다시 추출
  const found = extractArtifactCode();
  if (!found || !found.code || found.code.length < 80) {
    if (card) card.removeAttribute("data-slop-analyzed");
    return;
  }

  _lastArtifactKey = _artifactKey(found.code);

  const filename = guessFilenameFromCode(found.code);
  console.log(`[Slop Detector] 아티팩트 분석 시작: ${filename} (${found.code.length}자, 카드: ${!!card})`);

  analyzeAndRender(found.code, filename, (newEl) => {
    newEl.setAttribute("data-slop-artifact-panel", "1");
    newEl.style.margin = "8px 0";

    // 삽입 위치: 카드의 메시지 element 다음 — 옛 코드의 4단계 부모 hardcode 대신
    // semantic 매칭으로 안정성 확보
    function _insert() {
      const target =
        card?.closest("[data-message-author-role], .font-claude-message, [data-test-render-count]")
        || card?.parentElement?.parentElement?.parentElement?.parentElement
        || found.container;
      if (!target) return false;
      // 기존 형제 패널 제거
      let next = target.nextElementSibling;
      while (next?.hasAttribute("data-slop-artifact-panel")) {
        const toRemove = next; next = next.nextElementSibling; toRemove.remove();
      }
      try {
        target.insertAdjacentElement("afterend", newEl);
        return true;
      } catch { return false; }
    }

    const ok = _insert();
    if (!ok) {
      console.warn("[Slop Detector] 아티팩트 패널 삽입 타겟 없음");
      return false;
    }
    console.log("[Slop Detector] 아티팩트 패널 삽입 완료");

    // React reconciliation 대비: 사라지면 재삽입 (최대 5회, 30초 timeout)
    let reattempts = 0;
    const watcher = new MutationObserver(() => {
      if (!document.contains(newEl) && reattempts < 5) {
        reattempts++;
        console.log(`[Slop Detector] 패널 제거 감지, 재삽입 #${reattempts}`);
        _insert();
      }
    });
    watcher.observe(document.body, { childList: true, subtree: true });
    setTimeout(() => watcher.disconnect(), 30000);

    return true;
  });
}

// ── MutationObserver ──────────────────────────────────────────────────────────
const observer = new MutationObserver(() => {
  clearTimeout(observer._timer);
  observer._timer = setTimeout(() => {
    scanCodeBlocks();
    scanArtifacts();
    scanResponseText();
  }, 1500);
});

// ── 아티팩트 결과 수신 (postMessage from a.claude.ai iframe) ─────────────────
const _processedArtifactMessages = new Set();

window.addEventListener("message", (event) => {
  const allowed = ["https://a.claude.ai", "https://www.claudeusercontent.com"];
  if (!allowed.some(o => event.origin === o || event.origin.endsWith(".claudeusercontent.com"))) return;
  if (event.data?.type !== "SLOP_ARTIFACT_RESULT") return;
  const results = event.data.results;
  if (!results?.length) return;

  // 중복 방지: 패키지 조합 기반
  const msgKey = results.map(r => r.package).sort().join(",");
  if (_processedArtifactMessages.has(msgKey)) return;
  _processedArtifactMessages.add(msgKey);

  console.log(`[Slop Detector] 아티팩트 iframe 결과 수신:`, results.map(r => `${r.package}(${r.level})`));

  const panel = buildPanel(results);
  panel.setAttribute("data-slop-artifact-panel", "1");
  panel.style.margin = "4px 0 0";

  // 전략 1: artifact-block 카드 찾기
  const cards = [...document.querySelectorAll("[class*='artifact-block'], [class*='artifact-preview'], [class*='ArtifactPreview'], [data-testid*='artifact'], [aria-label*='artifact' i]")];
  const targetCard = cards.find(c => !c.hasAttribute("data-slop-analyzed"));

  if (targetCard) {
    targetCard.setAttribute("data-slop-analyzed", "1");
    const rowContainer = targetCard
      ?.parentElement?.parentElement?.parentElement?.parentElement;
    if (rowContainer) {
      let next = rowContainer.nextElementSibling;
      while (next?.hasAttribute("data-slop-artifact-panel")) {
        const toRemove = next;
        next = next.nextElementSibling;
        toRemove.remove();
      }
      try { rowContainer.insertAdjacentElement("afterend", panel); return; } catch {}
    }
  }

  // 전략 2: 대화 내 마지막 응답 블록 뒤에 삽입
  const responseBlocks = document.querySelectorAll(
    ".font-claude-message, [class*='prose'], div[data-is-streaming='false']"
  );
  const lastBlock = responseBlocks[responseBlocks.length - 1];
  if (lastBlock) {
    // 기존 아티팩트 패널이 있으면 제거
    const existing = lastBlock.parentElement?.querySelector("[data-slop-artifact-panel]");
    if (existing) existing.remove();
    try { lastBlock.insertAdjacentElement("afterend", panel); return; } catch {}
  }

  // 전략 3: 대화 컨테이너 끝에 추가
  const chatContainer = document.querySelector("[class*='conversation'], main, [role='main']");
  if (chatContainer) {
    try { chatContainer.appendChild(panel); } catch {}
  }
});

// ── 시작 ──────────────────────────────────────────────────────────────────────
(async () => {
  const serverUp = await checkApiServer();
  console.log(`[Slop Detector] 시작 — 사이트: claude, API: ${serverUp ? "✅ 연결됨" : "❌ 오프라인"}`);
  if (!serverUp) return;

  watchNavigation(() => {
    processedKeys = new Set();
    clearTimeout(_artifactTimer);
    _artifactTimer = null;
    _pendingCard = null;
    _lastArtifactKey = null;
    _processedArtifactMessages.clear();
    // 아티팩트 카드 분석 마킹 초기화
    document.querySelectorAll("[data-slop-analyzed]").forEach(el => el.removeAttribute("data-slop-analyzed"));
    document.querySelectorAll("[data-slop-artifact-panel]").forEach(el => el.remove());
    setTimeout(() => { scanCodeBlocks(); scanArtifacts(); }, 1000);
  });

  scanCodeBlocks();
  scanArtifacts();
  scanResponseText();
  observer.observe(document.body, { childList: true, subtree: true });
})();

// ── 텍스트 응답 스캔 (pip/npm install 패턴 + table td strong) ────────────────
const processedTextKeys = new Set();

// Claude 표시명 → PyPI/npm 패키지명 매핑
const CLAUDE_PACKAGE_MAP = {
  "scikit-learn": "scikit-learn",
  "sklearn": "scikit-learn",
  "tensorflow": "tensorflow",
  "pytorch": "torch",
  "keras": "keras",
  "xgboost": "xgboost",
  "lightgbm": "lightgbm",
  "hugging face": "transformers",
  "transformers": "transformers",
  "numpy": "numpy",
  "pandas": "pandas",
  "matplotlib": "matplotlib",
  "opencv": "opencv-python",
  "fastapi": "fastapi",
  "flask": "flask",
  "django": "django",
  "requests": "requests",
  "scipy": "scipy",
};

function extractTablePackages(el) {
  // Claude 표(table) 안의 td > strong 태그에서 패키지명 추출
  const packages = new Set();
  el.querySelectorAll("table td strong").forEach(strong => {
    const name = strong.textContent.trim().toLowerCase();
    if (CLAUDE_PACKAGE_MAP[name]) {
      packages.add(CLAUDE_PACKAGE_MAP[name]);
    } else if (/^[a-z0-9][a-z0-9\-\.]+$/.test(name) && name.length < 40) {
      packages.add(name);
    }
  });
  return [...packages];
}

function scanResponseText() {
  // Claude 응답 컨테이너
  document.querySelectorAll(
    ".prose, [class*='prose'], div[data-is-streaming='false'], .font-claude-message"
  ).forEach(el => {
    if (el.hasAttribute("data-slop-scanned")) return;
    // 코드블록 스캔이 이미 처리한 응답이면 텍스트 스캔 스킵 (패널 중복 방지)
    if (el.hasAttribute("data-slop-code-scanned")) return;
    if (el.closest("[data-slop-code-scanned]")) return;
    const text = el.innerText || "";
    if (text.length < 20) return;

    // 1. pip/npm install 패턴
    const pipPackages = extractPackagesFromText(text);

    // 2. table td > strong 태그 (Claude 패키지 소개 표)
    const tablePackages = extractTablePackages(el);

    // 3. 자연어 감지 — 백틱, import 패턴, 인기 패키지 매칭
    const nlpPackages = typeof extractPackagesFromNaturalText === "function"
      ? extractPackagesFromNaturalText(text)
      : [];

    const allPackages = [...new Set([...pipPackages, ...tablePackages, ...nlpPackages])]
      .filter(p => ![...processedKeys].some(k => k.includes(p)));

    if (!allPackages.length) return;

    // DOM에 이미 텍스트 패널이 있으면 스킵
    if (el.parentElement?.querySelector("[data-slop-text-panel]")) return;

    el.setAttribute("data-slop-scanned", "1");
    console.log(`[Slop Detector] Claude 텍스트 패키지 감지:`, allPackages);

    analyzePackagesFromText(allPackages, (newEl) => {
      newEl.setAttribute("data-slop-text-panel", "1");
      const existingPanel = el.nextElementSibling?.hasAttribute("data-slop-panel")
        ? el.nextElementSibling : null;
      const insertTarget = existingPanel || el;
      try { insertTarget.insertAdjacentElement("afterend", newEl); return true; } catch {}
      return false;
    });
  });
}
