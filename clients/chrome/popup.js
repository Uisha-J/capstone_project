/**
 * popup.js
 * 팝업 UI의 상태 업데이트 및 통계 표시를 담당합니다.
 */

document.addEventListener('DOMContentLoaded', () => {
  const dot = document.getElementById("dot");
  const text = document.getElementById("status-text");

  // 1. 서버(API) 연결 상태 확인
  chrome.runtime.sendMessage({ type: "HEALTH_CHECK" }, (res) => {
    if (res?.ok) {
      dot.className = "dot ok";
      text.textContent = "로컬 분석 엔진 연결됨 ✓";
    } else {
      dot.className = "dot error";
      text.textContent = "분석 엔진 오프라인 (Docker 확인)";
    }
  });

  // 2. background.js로부터 누적된 위협 통계 데이터 가져오기
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (stats) => {
    if (stats) {
      document.getElementById("stat-safe").textContent = stats.safe || 0;
      document.getElementById("stat-agent").textContent = stats.agentic || 0;
      document.getElementById("stat-sus").textContent = stats.suspicious || 0;
      document.getElementById("stat-mal").textContent = stats.malicious || 0;
    }
  });

  // 3. HMAC Secret 관리
  const hmacInput = document.getElementById("hmac-secret");
  const saveBtn = document.getElementById("save-secret");
  const statusEl = document.getElementById("secret-status");

  // 저장된 값 불러오기 (마스킹 표시)
  chrome.storage.sync.get(["hmacSecret"], (cfg) => {
    const s = cfg?.hmacSecret || "";
    statusEl.textContent = s ? `현재: 설정됨 (${s.length}자)` : "현재: 미설정 (인증 안 함)";
    hmacInput.placeholder = s ? "변경하려면 새 값 입력" : "비워두면 인증 안 함";
  });

  saveBtn.addEventListener("click", () => {
    const secret = hmacInput.value.trim();
    chrome.storage.sync.set({ hmacSecret: secret }, () => {
      statusEl.textContent = secret
        ? `저장됨 (${secret.length}자) — 어댑터 AISLOP_HMAC_SECRET 와 동일해야 함`
        : "삭제됨 — 인증 비활성화";
      hmacInput.value = "";
    });
  });
});