/**
 * common.js — 공통 유틸리티
 * claude.js / chatgpt.js / gemini.js 에서 공통으로 사용
 */

// ── 위험도 색상 (어댑터 V2 응답: CRITICAL/HIGH/MEDIUM/AGENTIC/LOW/UNKNOWN) ───
const LEVEL = {
  CRITICAL: { dot:"#ef4444", badge:"#ef4444", text:"#991b1b", label:"CRITICAL" },
  HIGH:     { dot:"#f97316", badge:"#f97316", text:"#9a3412", label:"HIGH"     },
  MEDIUM:   { dot:"#eab308", badge:"#eab308", text:"#713f12", label:"MEDIUM"   },
  AGENTIC:  { dot:"#a855f7", badge:"#a855f7", text:"#581c87", label:"AGENTIC"  },
  LOW:      { dot:"#22c55e", badge:"#22c55e", text:"#14532d", label:"LOW"      },
  UNKNOWN:  { dot:"#94a3b8", badge:"#94a3b8", text:"#475569", label:"UNKNOWN"  },
};

// V2 verdict → 한국어 라벨
const VERDICT_LABEL = {
  MALICIOUS:      "악성 패키지",
  HIGH_RISK:      "고위험",
  SUSPICIOUS:     "의심",
  AGENTIC:        "AI 에이전트 라이브러리",
  CLEAN:          "정상",
  CANNOT_ANALYZE: "레지스트리 미등록 (슬롭스쿼팅 강력 의심)",
  ERROR:          "분석 오류",
};

// HTML escape — V2 응답에 LLM 추론/코드가 포함되므로 안전 처리 필수
function _esc(text) {
  if (text == null) return "";
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ── background 통신 ──────────────────────────────────────────────────────────
function callBackground(message, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`타임아웃 (${timeoutMs / 1000}초 초과)`)),
      timeoutMs
    );
    chrome.runtime.sendMessage(message, (res) => {
      clearTimeout(timer);
      if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
      if (res?.error) return reject(new Error(res.error));
      resolve(res);
    });
  });
}

async function checkApiServer() {
  try { return (await callBackground({ type: "HEALTH_CHECK" }, 3000))?.ok === true; }
  catch { return false; }
}

// ── 텍스트에서 패키지명 추출 ─────────────────────────────────────────────────
// pip install, npm install 패턴을 텍스트 전체에서 탐지
function extractPackagesFromText(text) {
  const packages = new Set();

  const patterns = [
    // pip install pkg1 pkg2 / pip install pkg==1.0
    /(?:^|[\s`])(?:!|%)?pip(?:3)?\s+install\s+([\w\-\.\[\],\s>=<!]+?)(?=\n|$|`|;)/gm,
    // npm install pkg / npm i pkg
    /(?:^|[\s`])npm\s+(?:install|i)\s+([\w\-@\/\s]+?)(?=\n|$|`|;)/gm,
    // pip install -r 는 제외
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const raw = match[1];
      // 각 패키지명 파싱
      raw.split(/[\s,]+/).forEach(pkg => {
        // 버전 지정자 제거: requests>=2.0 → requests
        pkg = pkg.replace(/[><=!].*/,'').replace(/\[.*\]/,'').trim();
        // 유효성 검사
        if (pkg.length < 2) return;
        if (pkg.startsWith('-')) return;          // -r, --upgrade 등 플래그
        if (pkg.includes('.py')) return;          // 파일명
        if (/^[A-Z][A-Z]/.test(pkg)) return;     // 상수형 대문자
        if (/^\d/.test(pkg)) return;              // 숫자로 시작
        // 일반 영어 단어/언어 키워드 제외 (LLM 이 jum-bled pip install 명령 생성 시 오탐 방지)
        if (NLP_STOPWORDS.has(pkg.toLowerCase())) return;
        // import name → PyPI name 매핑 (cv2 → opencv-python 등)
        packages.add(_normalizeImportName(pkg));
      });
    }
  }

  return [...packages];
}

// ── 자연어 텍스트에서 패키지명 추출 (백틱 + import + 인기 패키지 매칭) ─────────
// pip install 패턴이 없는 텍스트 응답에서도 패키지명을 감지
const POPULAR_PACKAGES = new Set([
  // Python
  "numpy","pandas","flask","django","fastapi","requests","scipy","matplotlib",
  "tensorflow","pytorch","torch","keras","scikit-learn","sklearn","opencv-python",
  "pillow","beautifulsoup4","bs4","selenium","scrapy","celery","redis","sqlalchemy",
  "alembic","pydantic","httpx","aiohttp","uvicorn","gunicorn","pytest","black",
  "mypy","ruff","poetry","pipenv","transformers","datasets","langchain","openai",
  "anthropic","gradio","streamlit","plotly","seaborn","bokeh","dash","sympy",
  "networkx","nltk","spacy","gensim","xgboost","lightgbm","catboost","optuna",
  "ray","dask","polars","pyarrow","fastparquet","duckdb","pymongo","psycopg2",
  "mysqlclient","peewee","tortoise-orm","motor","mongoengine","marshmallow",
  "pyyaml","toml","dotenv","python-dotenv","click","typer","rich","tqdm",
  "loguru","sentry-sdk","cryptography","bcrypt","jwt","pyjwt","paramiko",
  "fabric","boto3","google-cloud-storage","azure-storage-blob",
  // npm
  "express","react","next","vue","nuxt","angular","svelte","axios","lodash",
  "moment","dayjs","date-fns","cheerio","puppeteer","playwright","jest","mocha",
  "chai","vitest","webpack","vite","rollup","esbuild","tailwindcss","prisma",
  "sequelize","mongoose","typeorm","knex","socket.io","ws","cors","helmet",
  "dotenv","jsonwebtoken","bcryptjs","passport","multer","sharp","nodemailer",
  "bull","ioredis","pg","mysql2","mongodb","zod","yup","joi",
]);

// ── import name → PyPI 패키지명 매핑 ─────────────────────────────────────────
// 많은 Python 패키지는 import 이름과 PyPI 이름이 다름
// 예: `import cv2` 의 PyPI 패키지는 opencv-python
// 이 매핑 없으면 "레지스트리 미등록 (슬롭스쿼팅)" 으로 잘못 판정됨
const IMPORT_TO_PYPI = {
  // 컴퓨터 비전 / ML
  "cv2": "opencv-python",
  "sklearn": "scikit-learn",
  "skimage": "scikit-image",
  "pil": "Pillow",
  "pytorch": "torch",   // PyPI 의 진짜 PyTorch 는 'torch' — 'pytorch' 는 placeholder/redirect
  "tf": "tensorflow",
  // 데이터
  "bs4": "beautifulsoup4",
  "yaml": "PyYAML",
  "dotenv": "python-dotenv",
  // 보안
  "crypto": "pycryptodome",
  "jwt": "PyJWT",
  // 시스템
  "serial": "pyserial",
  "usb": "pyusb",
  "magic": "python-magic",
  "levenshtein": "python-Levenshtein",
  "win32api": "pywin32",
  "win32con": "pywin32",
  "win32gui": "pywin32",
  "win32com": "pywin32",
  // 기타
  "discord": "discord.py",
  "telegram": "python-telegram-bot",
  "opengl": "PyOpenGL",
  "mysqldb": "mysqlclient",
  "openpyxl": "openpyxl",
  // import 이름이 자체 PyPI 이름인 일부 — 매핑 안 해도 됨 (생략)
};

function _normalizeImportName(name) {
  if (!name) return name;
  const lower = name.toLowerCase().trim();
  return IMPORT_TO_PYPI[lower] || name;
}

// 오탐 방지: 일반 영어 단어/프로그래밍 키워드
const NLP_STOPWORDS = new Set([
  "the","and","for","with","that","this","from","can","you","use","your",
  "will","not","are","have","more","any","all","it","is","in","or","as",
  "an","to","a","be","has","was","were","been","being","do","does","did",
  "but","if","then","else","when","where","how","what","which","who",
  "pip","npm","install","python","node","import","export","require","module",
  "function","class","def","return","const","let","var","true","false",
  "none","null","self","async","await","try","catch","finally","throw",
  "new","delete","typeof","instanceof","void","yield","super","extends",
  "implements","interface","enum","type","public","private","protected",
  "static","final","abstract","package","default","case","switch","break",
  "continue","while","for","do","if","else","elif","except","raise",
  "pass","lambda","with","as","global","nonlocal","assert","yield",
  "string","number","boolean","object","array","list","dict","set","tuple",
  "int","float","double","long","short","byte","char","bool","str",
  "print","console","log","error","warning","debug","info",
  "http","https","api","url","uri","html","css","json","xml","sql",
  "get","post","put","delete","patch","head","options",
  "app","server","client","database","table","column","row","key","value",
  "file","path","dir","folder","name","index","main","test","config",
  "data","model","view","controller","service","repository","handler",
  "input","output","result","response","request","query","param","body",
  "header","cookie","session","token","auth","user","admin","role",
  "code","script","style","image","video","audio","font","icon",
  "hello","world","example","sample","demo","foo","bar","baz",
]);

function extractPackagesFromNaturalText(text) {
  const found = new Set();

  // 1) 백틱 인라인 코드: `package-name`
  const backtickRe = /`([a-zA-Z][a-zA-Z0-9_\-\.]{1,40})`/g;
  let m;
  while ((m = backtickRe.exec(text)) !== null) {
    const raw = m[1].toLowerCase().trim();
    const name = _normalizeImportName(raw);
    if (_isLikelyPackage(name.toLowerCase())) found.add(name);
  }

  // 2) import 패턴 (코드블록 밖 텍스트에서도 감지)
  // import cv2 / from cv2 import ... → opencv-python 으로 매핑
  const importRe = /(?:^|\n)\s*(?:import\s+([\w\-]+)|from\s+([\w\-]+)\s+import)/gm;
  while ((m = importRe.exec(text)) !== null) {
    const raw = (m[1] || m[2]).trim();
    const name = _normalizeImportName(raw);
    if (_isLikelyPackage(name.toLowerCase())) found.add(name);
  }

  // 3) 인기 패키지 사전 매칭 (단어 경계 기반)
  for (const pkg of POPULAR_PACKAGES) {
    // 패키지명이 2글자 이하면 오탐 위험 → 스킵
    if (pkg.length <= 2) continue;
    // 단어 경계로 매칭 (대소문자 무시)
    const re = new RegExp(`(?:^|[\\s\`"'(\\[,;:])${escapeRegex(pkg)}(?:$|[\\s\`"')\\],;:.!?])`, "im");
    if (re.test(text)) found.add(_normalizeImportName(pkg));  // pytorch → torch 등 매핑
  }

  return [...found];
}

function _isLikelyPackage(name) {
  if (name.length < 2 || name.length > 40) return false;
  if (NLP_STOPWORDS.has(name)) return false;
  if (/^\d/.test(name)) return false;
  if (/\.(py|js|ts|html|css|json|md|txt|yaml|yml)$/i.test(name)) return false;
  // PascalCase 클래스명 제외: MyClass, ImageData
  if (/^[A-Z][a-z]+([A-Z][a-z]+)+$/.test(name)) return false;
  return true;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── 페이지 다크모드 감지 (배경 휘도 기반) ───────────────────────────────────
function _isDarkPage() {
  try {
    const bg = getComputedStyle(document.body).backgroundColor;
    const m = bg.match(/\d+/g);
    if (!m || m.length < 3) {
      return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
    }
    const [r, g, b] = m.slice(0, 3).map(Number);
    const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
    return lum < 0.5;
  } catch {
    return false;
  }
}

// 등급별 우선순위 (작을수록 위험)
const _LEVEL_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, AGENTIC: 3, UNKNOWN: 4, LOW: 5 };

// ── 패널 생성 (어댑터 V2 응답 기반) ──────────────────────────────────────────
// 입력 PackageResult 필드:
//   필수: package, ecosystem, level, verdict, is_agentic, evidence_count, reasons, ttp_ids
//   보강: confidence, version, engine_version, analyzed_at, ttp_details, code_snippets
//   D3 : closest_match
//   오류: error
function buildPanel(results) {
  // 위험도 순으로 정렬 (위험 → 미지 → 안전)
  const sorted = [...results].sort((a, b) => {
    const oa = _LEVEL_ORDER[a.level] ?? 99;
    const ob = _LEVEL_ORDER[b.level] ?? 99;
    return oa - ob;
  });
  // 카테고리별 카운트
  const dangerous = sorted.filter(r => !["LOW", "UNKNOWN"].includes(r.level));
  const unknown   = sorted.filter(r => r.level === "UNKNOWN");
  const safe      = sorted.filter(r => r.level === "LOW");
  // 가장 심각한 등급 (헤더 색상용)
  const worstLevel =
       dangerous.find(r => r.level === "CRITICAL") ? "CRITICAL"
    : dangerous.find(r => r.level === "HIGH")      ? "HIGH"
    : dangerous.find(r => r.level === "MEDIUM")    ? "MEDIUM"
    : dangerous.find(r => r.level === "AGENTIC")   ? "AGENTIC"
    : "LOW";
  const wc = LEVEL[worstLevel] || LEVEL.LOW;

  // 다크/라이트 테마 색 팔레트
  const dark = _isDarkPage();
  const T = dark ? {
    panelBg:   "#1e293b",  // slate-800
    panelBd:   "#334155",  // slate-700
    summaryBg: "#0f172a",  // slate-900
    detailBd:  "#334155",
    rowBd:     "#1e293b",
    title:     "#f1f5f9",  // slate-100
    sub:       "#94a3b8",  // slate-400
    counterOk: "#4ade80",  // green-400
    counterUn: "#94a3b8",
    chipSafeBg:"transparent",
    chipSafeTx:"#94a3b8",
    chipSafeBd:"#334155",
  } : {
    panelBg:   "#ffffff",
    panelBd:   dangerous.length ? wc.dot + "55" : "#d1fae5",
    summaryBg: dangerous.length ? wc.dot + "12" : "#f0fdf4",
    detailBd:  "#f1f5f9",
    rowBd:     "#f8fafc",
    title:     "#1e293b",
    sub:       "#64748b",
    counterOk: "#16a34a",
    counterUn: "#64748b",
    chipSafeBg:"transparent",
    chipSafeTx:"#64748b",
    chipSafeBd:"#cbd5e1",
  };

  // 칩 스타일러 (위험도에 따라 채움 강도 다르게)
  function chipStyle(level) {
    const c = LEVEL[level] || LEVEL.UNKNOWN;
    if (level === "CRITICAL" || level === "HIGH") {
      // 채워진 강한 색 + 흰글씨 (최대 가시성)
      return `background:${c.dot};color:#fff;border:1px solid ${c.dot};font-weight:600;`;
    }
    if (level === "MEDIUM" || level === "AGENTIC") {
      // 중간 강도
      return `background:${c.dot}33;color:${dark ? c.dot : c.text};border:1px solid ${c.dot};`;
    }
    if (level === "UNKNOWN") {
      // 점선 회색
      return `background:transparent;color:${T.chipSafeTx};border:1px dashed ${c.dot};`;
    }
    // LOW (안전)
    return `background:${T.chipSafeBg};color:${T.chipSafeTx};border:1px solid ${T.chipSafeBd};opacity:0.7;`;
  }

  const panel = document.createElement("div");
  panel.setAttribute("data-slop-panel", "1");
  panel.style.cssText = `
    margin:4px 0 6px;
    border:1px solid ${T.panelBd};
    border-left:4px solid ${dangerous.length ? wc.dot : (unknown.length ? LEVEL.UNKNOWN.dot : "#22c55e")};
    border-radius:6px; overflow:hidden;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    font-size:12px; background:${T.panelBg};
  `;

  // 카운터 HTML (위험/미지/안전)
  const counters = [];
  if (dangerous.length) counters.push(`<span style="color:${wc.dot};font-weight:600;">⚠ 위험 ${dangerous.length}</span>`);
  if (unknown.length)   counters.push(`<span style="color:${T.counterUn};">❓ 미지 ${unknown.length}</span>`);
  if (safe.length)      counters.push(`<span style="color:${T.counterOk};">✓ 안전 ${safe.length}</span>`);
  if (!counters.length) counters.push(`<span style="color:${T.counterOk};">이상 없음</span>`);

  // 요약 행 — 카운터 + 칩 목록
  const summary = document.createElement("div");
  summary.style.cssText = `
    display:flex; align-items:center; gap:8px; padding:6px 10px;
    background:${T.summaryBg};
    cursor:pointer; user-select:none;
  `;
  summary.innerHTML = `
    <b style="color:${T.title};font-size:12px;flex-shrink:0;">Slop Detector</b>
    <span style="display:flex;gap:8px;font-size:11px;flex-shrink:0;">
      ${counters.join('<span style="color:'+T.sub+';">·</span>')}
    </span>
    <span style="display:flex;gap:4px;flex-wrap:wrap;flex:1;min-width:0;">
      ${sorted.map(r => {
        return `<span style="
          display:inline-flex;align-items:center;
          padding:2px 7px;border-radius:99px;font-size:10px;
          font-family:ui-monospace,'SF Mono',monospace;
          ${chipStyle(r.level)}
        ">${_esc(r.package)}</span>`;
      }).join("")}
    </span>
    <span class="slop-toggle" style="color:${T.sub};font-size:11px;flex-shrink:0;">▸ 상세</span>
  `;
  panel.appendChild(summary);

  // 상세 영역 — 각 패키지마다 row
  const detail = document.createElement("div");
  detail.style.cssText = `display:none;border-top:1px solid ${T.detailBd};`;

  // 정보 박스 스타일러 — 다크/라이트 모드 모두 대응
  function boxStyle(accent, lightBg, lightText, darkText) {
    const bg = dark ? accent + "1f" : lightBg;
    const tx = dark ? darkText : lightText;
    return `margin:0 0 5px 12px;padding:5px 8px;background:${bg};border-left:2px solid ${accent};border-radius:0 3px 3px 0;font-size:11px;color:${tx};`;
  }

  sorted.forEach(r => {
    const c = LEVEL[r.level] || LEVEL.UNKNOWN;
    const verdictLabel = VERDICT_LABEL[r.verdict] || r.verdict || "?";

    const row = document.createElement("div");
    row.style.cssText = `padding:8px 10px;border-bottom:1px solid ${T.rowBd};`;

    // ── 헤더: 패키지명 · level · verdict · confidence ──────────
    const confidencePct = (typeof r.confidence === "number" && r.confidence > 0)
      ? Math.round(r.confidence * 100) : null;
    const verBadge = r.version
      ? ` <span style="color:${T.sub};font-size:10px;">v${_esc(r.version)}</span>` : "";
    row.innerHTML = `
      <div style="display:flex;align-items:center;gap:5px;margin-bottom:5px;flex-wrap:wrap;">
        <span style="width:7px;height:7px;border-radius:50%;background:${c.dot};display:inline-block;"></span>
        <b style="font-family:monospace;color:${T.title};">${_esc(r.package)}</b>${verBadge}
        <span style="padding:1px 6px;border-radius:99px;font-size:10px;font-weight:700;background:${c.badge};color:#fff;">${c.label}</span>
        <span style="color:${T.sub};font-size:11px;">${_esc(verdictLabel)}</span>
        ${confidencePct !== null
          ? `<span style="color:${T.sub};font-size:10px;">· LLM 신뢰도 ${confidencePct}%</span>`
          : ""}
        ${r.evidence_count
          ? `<span style="color:${T.sub};font-size:10px;">· 근거 ${r.evidence_count}건</span>`
          : ""}
      </div>
    `;

    // ── AGENTIC 안내 박스 ─────────────────────────────────────
    if (r.is_agentic || r.verdict === "AGENTIC") {
      const note = document.createElement("div");
      note.style.cssText = boxStyle("#a855f7", "#faf5ff", "#581c87", "#e9d5ff");
      note.innerHTML = `🤖 <b>AI 에이전트 라이브러리</b> — 악성 아님. 의도적으로 도입한 경우에만 사용하세요.`;
      row.appendChild(note);
    }

    // ── CANNOT_ANALYZE 강한 경고 박스 ─────────────────────────
    if (r.verdict === "CANNOT_ANALYZE") {
      const warn = document.createElement("div");
      warn.style.cssText = boxStyle("#ef4444", "#fef2f2", "#991b1b", "#fecaca");
      warn.innerHTML = `⚠️ <b>레지스트리에 등록되지 않은 패키지입니다.</b> LLM 환각으로 생성된 이름일 가능성이 매우 높습니다 (슬롭스쿼팅).`;
      row.appendChild(warn);
    }

    // ── 추정 정상명 (closest_match) ────────────────────────────
    if (r.closest_match && r.closest_match !== r.package) {
      const close = document.createElement("div");
      close.style.cssText = boxStyle("#06b6d4", "#ecfeff", "#155e75", "#a5f3fc");
      const codeBg = dark ? "#155e7544" : "#cffafe";
      const codeColor = dark ? "#cffafe" : "#155e75";
      close.innerHTML = `💡 <b>추정 정상 패키지: <code style="background:${codeBg};color:${codeColor};padding:1px 4px;border-radius:3px;">${_esc(r.closest_match)}</code></b> — 오타/환각이라면 이걸로 교체하세요.`;
      row.appendChild(close);
    }

    // ── TTP (공격 기법) 상세 ───────────────────────────────────
    const ttpDetails = Array.isArray(r.ttp_details) ? r.ttp_details.filter(t => t && (t.id || t.name)) : [];
    const ttpIds = Array.isArray(r.ttp_ids) ? r.ttp_ids.filter(Boolean) : [];
    if (ttpDetails.length > 0 || ttpIds.length > 0) {
      const ttp = document.createElement("div");
      ttp.style.cssText = boxStyle("#f97316", "#fff7ed", "#7c2d12", "#fed7aa");
      const ttpTitleColor = dark ? "#fdba74" : "#9a3412";
      const ttpCodeBg = dark ? "#7c2d1244" : "#ffedd5";
      const ttpCodeColor = dark ? "#fed7aa" : "#7c2d12";
      let html = `<b style="color:${ttpTitleColor};">🎯 탐지된 TTP</b><br>`;
      if (ttpDetails.length > 0) {
        html += ttpDetails.slice(0, 5).map(t => {
          const id = _esc(t.id || "?");
          const name = t.name ? ` ${_esc(t.name)}` : "";
          const sev = t.severity ? ` <span style="color:${T.sub};">(${_esc(t.severity)})</span>` : "";
          if (t.url) {
            return `· <a href="${_esc(t.url)}" target="_blank" rel="noopener" style="color:${ttpTitleColor};text-decoration:underline;font-family:monospace;">${id}</a>${name}${sev}`;
          }
          return `· <code style="background:${ttpCodeBg};color:${ttpCodeColor};padding:1px 4px;border-radius:3px;">${id}</code>${name}${sev}`;
        }).join("<br>");
      } else {
        html += ttpIds.slice(0, 5).map(id =>
          `· <code style="background:${ttpCodeBg};color:${ttpCodeColor};padding:1px 4px;border-radius:3px;">${_esc(id)}</code>`
        ).join(" ");
      }
      ttp.innerHTML = html;
      row.appendChild(ttp);
    }

    // ── LLM 추론 ──────────────────────────────────────────────
    const reasons = Array.isArray(r.reasons) ? r.reasons.filter(Boolean) : [];
    if (reasons.length > 0) {
      const reason = document.createElement("div");
      reason.style.cssText = boxStyle("#94a3b8", "#f8fafc", "#475569", "#cbd5e1");
      reason.innerHTML =
        `<b>🤔 LLM 분석:</b><br>` +
        reasons.slice(0, 3).map(rs => `· ${_esc(rs)}`).join("<br>");
      row.appendChild(reason);
    }

    // ── 의심 코드 스니펫 ──────────────────────────────────────
    const snippets = Array.isArray(r.code_snippets) ? r.code_snippets.filter(Boolean) : [];
    if (snippets.length > 0) {
      const snip = document.createElement("div");
      snip.style.cssText = boxStyle("#ef4444", "#fef2f2", "#7f1d1d", "#fecaca")
        + "font-size:10px;font-family:monospace;white-space:pre-wrap;overflow-x:auto;max-height:120px;";
      const text = snippets[0].length > 400 ? snippets[0].slice(0, 400) + "..." : snippets[0];
      snip.textContent = "📄 " + text;
      row.appendChild(snip);
    }

    // ── 분석 에러 ─────────────────────────────────────────────
    if (r.error) {
      const err = document.createElement("div");
      err.style.cssText = boxStyle("#71717a", "#fafafa", "#52525b", "#d4d4d8");
      err.innerHTML = `❌ <b>분석 오류:</b> <code>${_esc(r.error)}</code>`;
      row.appendChild(err);
    }

    detail.appendChild(row);
  });

  panel.appendChild(detail);

  // 토글
  let open = dangerous.length > 0;
  detail.style.display = open ? "block" : "none";
  summary.querySelector(".slop-toggle").textContent = open ? "▾ 닫기" : "▸ 상세";
  summary.addEventListener("click", () => {
    open = !open;
    detail.style.display = open ? "block" : "none";
    summary.querySelector(".slop-toggle").textContent = open ? "▾ 닫기" : "▸ 상세";
  });

  return panel;
}

// ── 공통 분석 실행 ─────────────────────────────────────────────────────────────
async function analyzeAndRender(code, filename, insertFn) {
  const loading = document.createElement("div");
  loading.setAttribute("data-slop-panel", "1");
  loading.style.cssText = "font-size:11px;color:#94a3b8;padding:3px 2px;font-family:sans-serif;";
  loading.textContent = "🔍 Slop Detector 분석 중...";

  if (!insertFn(loading)) return;

  try {
    const result = await callBackground({ type: "PARSE_AND_ANALYZE", filename, code });
    loading.remove();
    const items = Array.isArray(result) ? result : result?.results;
    if (!items?.length) return;
    console.log(`[Slop Detector] 완료:`, items.map(r => `${r.package}(${r.level})`));
    insertFn(buildPanel(items));
  } catch (err) {
    console.error("[Slop Detector] 오류:", err.message);
    loading.textContent = `⚠️ Slop Detector 오류: ${err.message}`;
    setTimeout(() => loading.remove(), 5000);
  }
}

// ── 텍스트에서 직접 패키지 분석 ──────────────────────────────────────────────
async function analyzePackagesFromText(packages, insertFn) {
  if (!packages.length) return;

  const loading = document.createElement("div");
  loading.setAttribute("data-slop-panel", "1");
  loading.style.cssText = "font-size:11px;color:#94a3b8;padding:3px 2px;font-family:sans-serif;";
  loading.textContent = "🔍 Slop Detector 분석 중...";
  if (!insertFn(loading)) return;

  try {
    const result = await callBackground({ type: "ANALYZE_PACKAGES", packages });
    loading.remove();
    // 백엔드 응답 정규화: {results: [...]} 객체 또는 [...] 배열 양쪽 지원
    const items = Array.isArray(result) ? result : result?.results;
    if (!items?.length) return;
    console.log(`[Slop Detector] 텍스트 분석 완료:`, items.map(r => `${r.package}(${r.level})`));
    insertFn(buildPanel(items));
  } catch (err) {
    console.error("[Slop Detector] 오류:", err.message);
    loading.textContent = `⚠️ Slop Detector 오류: ${err.message}`;
    setTimeout(() => loading.remove(), 5000);
  }
}

// ── SPA 네비게이션 감지 ───────────────────────────────────────────────────────
function watchNavigation(onNavigate) {
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      console.log("[Slop Detector] 페이지 이동 감지 → 상태 초기화");
      document.querySelectorAll("[data-slop-panel]").forEach(el => el.remove());
      onNavigate();
    }
  }).observe(document.body, { childList: true, subtree: true });
}
