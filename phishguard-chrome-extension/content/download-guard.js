(() => {
  if (window.__phishGuardDownloadGuardLoaded) return;
  window.__phishGuardDownloadGuardLoaded = true;
  let enabled = true;
  let currentAnchor = null;
  let hoverTimer = null;
  let requestSeq = 0;
  const cache = new Map();
  const bypass = new WeakSet();
  const badgeId = "phishguard-site-badge";
  const downloadableExt = /\.(?:exe|msi|msp|com|scr|bat|cmd|ps1|vbs|js|jar|apk|dmg|pkg|zip|rar|7z|tar|gz|iso|img|docm|xlsm|pptm|pdf|docx?|xlsx?|pptx?|csv|rtf|eml|msg|svg|html?)$/i;
  function linkInfo(a) {
    let url; try { url = new URL(a.href, location.href); } catch { return null; }
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname) return null;
    let path = url.pathname || "";
    try { path = decodeURIComponent(path); } catch { /* Keep encoded path if malformed. */ }
    const text = `${a.innerText || ""} ${a.getAttribute("aria-label") || ""} ${a.getAttribute("title") || ""}`.toLowerCase();
    const isFile = a.hasAttribute("download") || downloadableExt.test(path) || /\b(download|save file|export file|attachment)\b/.test(text) || /[?&](?:download|attachment|export)=?(?:1|true|yes)?(?:&|$)/i.test(url.search);
    return { url: url.href, host: url.hostname, isFile, name: a.getAttribute("download") || path.split("/").filter(Boolean).pop() || String(a.innerText || "").trim() || url.hostname };
  }
  function installStyle() {
    if (document.getElementById("phishguard-site-style")) return;
    const s = document.createElement("style"); s.id = "phishguard-site-style";
    s.textContent = `@keyframes pgDownloadPulse{0%,100%{outline-color:#d97706;background-color:rgba(217,119,6,.04)}50%{outline-color:#fbbf24;background-color:rgba(251,191,36,.2)}}.pg-link-checking{outline:2px solid #d97706!important;outline-offset:2px!important;animation:pgDownloadPulse .9s ease-in-out infinite!important}.pg-link-safe{outline:2px solid #16834a!important;outline-offset:2px!important}.pg-link-warn{outline:2px solid #d97706!important;outline-offset:2px!important}.pg-link-danger{outline:2px solid #b42318!important;outline-offset:2px!important}#${badgeId}{position:fixed!important;z-index:2147483647!important;right:14px!important;bottom:14px!important;max-width:min(380px,calc(100vw - 28px))!important;padding:10px 13px!important;border-radius:10px!important;box-shadow:0 7px 25px #0003!important;font:12px/1.4 system-ui,sans-serif!important;color:#fff!important;background:#344054!important;pointer-events:none!important;overflow-wrap:anywhere!important}#${badgeId}.pg-safe{background:#16794b!important}#${badgeId}.pg-warn{background:#9a6700!important}#${badgeId}.pg-danger{background:#b42318!important}`;
    (document.head || document.documentElement).append(s);
  }
  function showBadge(text, kind = "") {
    let b = document.getElementById(badgeId);
    if (!b) { b = document.createElement("div"); b.id = badgeId; document.documentElement.append(b); }
    b.className = kind ? `pg-${kind}` : ""; b.textContent = `PhishGuard · ${text}`;
  }
  function clearHighlight(a) { if (a) a.classList.remove("pg-link-checking", "pg-link-safe", "pg-link-warn", "pg-link-danger"); }
  async function scan(url) {
    const cached = cache.get(url);
    if (cached && Date.now() - cached.at < 60_000) return cached.result;
    const response = await chrome.runtime.sendMessage({ type: "PHISHGUARD_CHECK_URL", url });
    if (!response?.ok) throw new Error(response?.error || "Check unavailable");
    cache.set(url, { at: Date.now(), result: response });
    if (cache.size > 500) cache.delete(cache.keys().next().value);
    return response;
  }
  function applyResult(a, info, result) {
    clearHighlight(a);
    if (result.status === "danger") { a.classList.add("pg-link-danger"); showBadge(`HIGH RISK · ${info.host} · do not download/open`, "danger"); }
    else if (result.status === "caution") { a.classList.add("pg-link-warn"); showBadge(`SUSPICIOUS · ${info.host} · verify before opening`, "warn"); }
    else if (result.status === "no_threat_detected" && result.hasLive) { a.classList.add("pg-link-safe"); showBadge(`${info.isFile ? "FILE LINK" : "LINK"} · No threat detected · ${info.host}`, "safe"); }
    else { a.classList.add("pg-link-warn"); showBadge(`CHECK INCONCLUSIVE · ${info.host} · reputation not confirmed`, "warn"); }
  }
  async function onHover(event) {
    if (!enabled) return;
    const a = event.target?.closest?.("a[href]");
    if (!a) return;
    const info = linkInfo(a); if (!info) return;
    if (currentAnchor === a) return;
    if (currentAnchor) clearHighlight(currentAnchor);
    currentAnchor = a; const seq = ++requestSeq; clearTimeout(hoverTimer);
    a.classList.add("pg-link-checking");
    hoverTimer = setTimeout(async () => {
      if (!enabled || seq !== requestSeq || currentAnchor !== a) return;
      showBadge(`${info.isFile ? "Checking file download" : "Checking link"} · ${info.host}…`);
      try { const result = await scan(info.url); if (!enabled || seq !== requestSeq || currentAnchor !== a) return; applyResult(a, info, result); }
      catch (error) {
      clearHighlight(a); a.classList.add("pg-link-warn");
      const reason = String(error?.message || "Backend request failed").replace(/\s+/g, " ").slice(0, 150);
      showBadge(`CHECK UNAVAILABLE · ${info.host} · ${reason}`, "warn");
    }
    }, 250);
  }
  function onMouseOut(event) {
    const a = event.target?.closest?.("a[href]");
    if (a && a === currentAnchor && !a.contains(event.relatedTarget)) { clearTimeout(hoverTimer); clearHighlight(a); currentAnchor = null; requestSeq++; document.getElementById(badgeId)?.remove(); }
  }
  async function onClick(event) {
    if (!enabled || event.defaultPrevented) return;
    const a = event.target?.closest?.("a[href]");
    if (!a || bypass.has(a)) { if (a) bypass.delete(a); return; }
    if (!event.isTrusted) return;
    const info = linkInfo(a);
    if (!info || !info.isFile) return;
    // Stop the download/navigation immediately while the reputation check runs.
    event.preventDefault(); event.stopImmediatePropagation();
    const originalText = a.textContent?.trim() || info.name || info.host;
    showBadge(`Checking download · ${info.host}…`);
    a.classList.add("pg-link-checking");
    try {
      const result = await scan(info.url);
      clearHighlight(a);
      if (result.status === "danger") {
        a.classList.add("pg-link-danger"); showBadge(`DOWNLOAD BLOCKED · ${info.host}`, "danger");
        window.alert(`PhishGuard blocked this download because the URL was rated high risk.\n\n${info.name || originalText}`);
        return;
      }
      if (result.status !== "no_threat_detected" || !result.hasLive) {
        a.classList.add("pg-link-warn"); showBadge(`CHECK ${result.status === "caution" ? "SUSPICIOUS" : "INCONCLUSIVE"} · ${info.host}`, "warn");
        const message = result.status === "caution" ? "PhishGuard found suspicious indicators." : "PhishGuard could not confirm this download is safe.";
        if (!window.confirm(`${message}\n\nFile/link: ${info.name || info.host}\n\nContinue anyway?`)) return;
      } else {
        a.classList.add("pg-link-safe"); showBadge(`NO THREAT DETECTED · ${info.host}`, "safe");
      }
      // Re-fire the link once after scanning; the bypass prevents a second scan.
      bypass.add(a);
      a.click();
      setTimeout(() => bypass.delete(a), 1000);
    } catch (error) {
      clearHighlight(a); a.classList.add("pg-link-warn");
      const reason = String(error?.message || "Backend request failed").replace(/\s+/g, " ").slice(0, 220);
      showBadge(`CHECK UNAVAILABLE · ${info.host} · ${reason}`, "warn");
      if (window.confirm(`PhishGuard could not check this download.\n\nReason: ${reason}\n\n${info.name || info.host}\n\nContinue without a result?`)) { bypass.add(a); a.click(); setTimeout(() => bypass.delete(a), 1000); }
    }
  }
  function setEnabled(value) {
    enabled = value;
    if (!enabled) { clearTimeout(hoverTimer); clearHighlight(currentAnchor); currentAnchor = null; requestSeq++; document.getElementById(badgeId)?.remove(); }
    else { installStyle(); showBadge("Hover checks and pre-download protection enabled."); }
  }
  chrome.runtime.onMessage.addListener(message => {
    if (message?.type === "PHISHGUARD_SITE_GUARD_ENABLE") setEnabled(true);
    if (message?.type === "PHISHGUARD_SITE_GUARD_DISABLE") setEnabled(false);
  });
  document.addEventListener("mouseover", onHover, true);
  document.addEventListener("focusin", onHover, true);
  document.addEventListener("mouseout", onMouseOut, true);
  document.addEventListener("click", onClick, true);
  installStyle();
})();
