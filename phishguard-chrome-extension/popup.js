const $ = id => document.getElementById(id);
$("openDashboard")?.addEventListener("click", () => chrome.runtime.openOptionsPage());
let currentTab = null;
const CONTENT_SCRIPT_ID = "phishguard-global-site-protection";
function normaliseBase(value) {
  const u = new URL(value.trim());
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Backend must use http:// or https://.");
  if (u.username || u.password) throw new Error("Do not put credentials in the backend URL.");
  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol === "http:" && !localHost) throw new Error("Use HTTPS for a remotely hosted backend. HTTP is allowed only for localhost.");
  const pathname = u.pathname.replace(/\/+$/, "").replace(/\/api$/i, "");
  return u.origin + pathname;
}
function showResult(target, report, prefix = "") {
  target.classList.remove("hidden"); target.replaceChildren();
  const score = Number.isFinite(Number(report.score)) ? Number(report.score) : null;
  const level = report.level || "Unknown";
  const h = document.createElement("h3"); h.textContent = prefix + (report.status === "danger" ? "High risk" : report.status === "caution" ? "Suspicious link" : report.status === "no_threat_detected" ? "No threat detected" : score === null ? "Scan result unavailable" : `${level} risk`); target.append(h);
  if (score !== null) { const s = document.createElement("div"); s.className = "score " + String(level).toLowerCase(); s.textContent = `${score}/100`; target.append(s); }
  const summary = document.createElement("p"); summary.textContent = report.summary || (report.status === "inconclusive" ? "No conclusive reputation result was available." : report.status === "no_threat_detected" ? "No known threat was returned by the available checks." : "Review the findings below."); target.append(summary);
  const findings = Array.isArray(report.findings) ? report.findings.slice(0, 8) : [];
  findings.forEach(f => { const p = document.createElement("p"); p.textContent = `${f.title || "Finding"}: ${f.detail || ""}`; target.append(p); });
}
async function sendBackend(payload) {
  const response = await chrome.runtime.sendMessage({ type: "PHISHGUARD_ANALYZE", payload });
  if (!response || !response.ok) throw new Error(response?.error || "Could not reach the backend.");
  return response.data;
}
async function isProtectionRegistered() {
  const registered = await chrome.scripting.getRegisteredContentScripts();
  const granted = await chrome.permissions.contains({ origins: ["http://*/*", "https://*/*"] });
  return granted && registered.some(item => item.id === CONTENT_SCRIPT_ID);
}
async function refreshSettings() {
  const data = await chrome.storage.local.get(["backendUrl"]);
  $("backendUrl").value = data.backendUrl || "";
  $("modeLabel").textContent = data.backendUrl ? "Backend URL configured" : "Backend not configured";
  try {
    const active = await isProtectionRegistered();
    $("toggleProtection").textContent = active ? "Disable download & hover protection" : "Enable download & hover protection on all websites";
  } catch { $("toggleProtection").textContent = "Enable download & hover protection on all websites"; }
  try { [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true }); } catch { currentTab = null; }
}
$("saveBackend").addEventListener("click", async () => {
  const button = $("saveBackend"); button.disabled = true;
  try {
    const base = normaliseBase($("backendUrl").value);
    const origin = new URL(base).origin;
    const granted = await chrome.permissions.request({ origins: [origin + "/*"] });
    if (!granted) throw new Error("Permission to contact this backend was not granted.");
    await chrome.storage.local.set({ backendUrl: base });
    $("modeLabel").textContent = "Backend URL configured";
    const health = await chrome.runtime.sendMessage({ type: "PHISHGUARD_HEALTH" });
    if (!health?.ok) throw new Error("Saved URL, but health check failed: " + (health?.error || "unknown error"));
    $("connectionStatus").textContent = "Connected to PhishGuard backend.";
    $("connectionStatus").className = "status low";
  } catch (e) {
    $("connectionStatus").textContent = e.message || "Could not save backend.";
    $("connectionStatus").className = "status high";
  } finally { button.disabled = false; }
});
$("scanPage").addEventListener("click", async () => {
  const b = $("scanPage"); b.disabled = true;
  $("pageResult").classList.remove("hidden"); $("pageResult").textContent = "Checking current page URL…";
  try {
    if (!currentTab?.url) throw new Error("Could not read the current tab URL. Try a normal website tab.");
    const u = new URL(currentTab.url);
    if (!["http:", "https:"].includes(u.protocol)) throw new Error("This browser page cannot be scanned.");
    const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_CHECK_URL", url: u.href });
    if (!result?.ok) throw new Error(result?.error || "URL check failed.");
    showResult($("pageResult"), result, "Website · ");
  } catch (e) { $("pageResult").classList.remove("hidden"); $("pageResult").textContent = e.message || "Could not scan this website."; }
  finally { b.disabled = false; }
});
$("toggleProtection").addEventListener("click", async () => {
  const button = $("toggleProtection"); button.disabled = true;
  try {
    const active = await isProtectionRegistered();
    if (active) {
      await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] }).catch(() => {});
      await chrome.storage.local.set({ siteProtectionEnabled: false });
      const tabs = await chrome.tabs.query({});
      await Promise.all(tabs.filter(t => t.id != null).map(t => chrome.tabs.sendMessage(t.id, { type: "PHISHGUARD_SITE_GUARD_DISABLE" }).catch(() => {})));
      button.textContent = "Enable download & hover protection on all websites";
      $("connectionStatus").textContent = "Website hover checks and pre-download checks disabled.";
    } else {
      const granted = await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] });
      if (!granted) throw new Error("Site access was not granted. Protection remains disabled.");
      await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] }).catch(() => {});
      await chrome.scripting.registerContentScripts([{ id: CONTENT_SCRIPT_ID, matches: ["http://*/*", "https://*/*"], js: ["content/download-guard.js"], runAt: "document_idle", allFrames: false, persistAcrossSessions: true }]);
      await chrome.storage.local.set({ siteProtectionEnabled: true });
      // Inject into already-open websites immediately; future page loads use the registered script.
      const tabs = await chrome.tabs.query({});
      await Promise.all(tabs.filter(t => t.id != null && /^https?:/.test(t.url || "")).map(async tab => {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content/download-guard.js"] }).catch(() => {});
        await chrome.tabs.sendMessage(tab.id, { type: "PHISHGUARD_SITE_GUARD_ENABLE" }).catch(() => {});
      }));
      button.textContent = "Disable download & hover protection";
      $("connectionStatus").textContent = "Protection enabled. Links are checked on hover; file-download links are checked before opening.";
    }
    $("connectionStatus").className = "status";
  } catch (e) {
    $("connectionStatus").textContent = e.message || "Could not update website protection.";
    $("connectionStatus").className = "status high";
  } finally { button.disabled = false; }
});
refreshSettings();
