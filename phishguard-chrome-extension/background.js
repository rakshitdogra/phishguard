const API_TIMEOUT_MS = 15000;

const CSV_RULE_ID_START = 1000;
const CSV_RULE_LIMIT = 4500;
function csvSourcesFromStorage(data) {
  return Array.isArray(data?.blockedCsvSources) ? data.blockedCsvSources : [];
}
function csvEntryMatches(entry, url) {
  if (!entry || entry.action === "allow" && !entry.value) return false;
  try {
    const parsed = new URL(url);
    if (entry.type === "domain") {
      const domain = String(entry.value || "").toLowerCase().replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
      return !!domain && (parsed.hostname.toLowerCase() === domain || parsed.hostname.toLowerCase().endsWith("." + domain));
    }
    if (entry.type === "url") {
      try { return parsed.href === new URL(String(entry.value || "")).href; }
      catch { return false; }
    }
    if (entry.type === "pattern") {
      const pattern = String(entry.value || "").toLowerCase();
      if (pattern.startsWith("||") && pattern.endsWith("^")) {
        const domain = pattern.slice(2, -1).toLowerCase();
        return parsed.hostname.toLowerCase() === domain || parsed.hostname.toLowerCase().endsWith("." + domain);
      }
      return parsed.href.toLowerCase().includes(pattern);
    }
  } catch {}
  return false;
}
async function findCsvDecision(url) {
  const data = await chrome.storage.local.get("blockedCsvSources");
  const matches = [];
  for (const source of csvSourcesFromStorage(data)) {
    if (source.enabled === false || !Array.isArray(source.entries)) continue;
    for (const entry of source.entries) {
      if (entry.enabled === false || !csvEntryMatches(entry, url)) continue;
      matches.push({ source: source.name || "CSV list", mode: source.mode || (String(entry.action).toLowerCase() === "allow" ? "whitelist" : "blacklist"), entry });
    }
  }
  // Explicit allow rows override CSV block rows. They only override local CSV rules, not backend reputation checks.
  const allow = matches.find(m => m.mode === "whitelist");
  if (allow) return { decision: "allow", source: allow.source, reason: allow.entry.reason || "Allowed by CSV rule." };
  const block = matches.find(m => m.mode !== "whitelist");
  if (block) return { decision: "block", source: block.source, reason: block.entry.reason || "This website matches an enabled CSV blocklist." };
  return null;
}
function dnrFilterForEntry(entry) {
  const type = String(entry.type || "");
  const value = String(entry.value || "").trim();
  if (!value) return null;
  if (type === "domain") {
    let host = value.toLowerCase().replace(/^\*\./, "").replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/^\.+|\.+$/g, "");
    if (!host || /[^a-z0-9.-]/i.test(host) || host.includes("..")) return null;
    return `||${host}^`;
  }
  if (type === "url") {
    try { const u = new URL(value); if (!['http:', 'https:'].includes(u.protocol)) return null; return `|${u.origin}${u.pathname}${u.search}^`; } catch { return null; }
  }
  if (type === "pattern" && /^\|\|[a-z0-9.-]+\^$/i.test(value)) return value.toLowerCase();
  return null;
}
let csvRulesSyncQueue = Promise.resolve();
function syncCsvDynamicRules() {
  const run = csvRulesSyncQueue.catch(() => {}).then(async () => {
    if (!chrome.declarativeNetRequest?.updateDynamicRules) return;
    const data = await chrome.storage.local.get(["blockedCsvSources", "csvBlockingEnabled"]);
    const rules = [];
    if (data.csvBlockingEnabled === true) {
      for (const source of csvSourcesFromStorage(data)) {
        if (source.enabled === false || !Array.isArray(source.entries)) continue;
        for (const entry of source.entries) {
          if (entry.enabled === false) continue;
          const filter = dnrFilterForEntry(entry);
          if (!filter) continue;
          const action = source.mode === "whitelist" || (!source.mode && String(entry.action || "block").toLowerCase() === "allow") ? "allow" : "block";
          rules.push({
            id: CSV_RULE_ID_START + rules.length,
            priority: action === "allow" ? 2 : 1,
            action: { type: action },
            condition: { urlFilter: filter, resourceTypes: ["main_frame"] }
          });
          if (rules.length >= CSV_RULE_LIMIT) break;
        }
        if (rules.length >= CSV_RULE_LIMIT) break;
      }
    }
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.filter(r => r.id >= CSV_RULE_ID_START && r.id < CSV_RULE_ID_START + CSV_RULE_LIMIT).map(r => r.id);
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: rules });
  });
  csvRulesSyncQueue = run;
  return run;
}
chrome.runtime.onInstalled.addListener(() => { syncCsvDynamicRules().catch(() => {}); syncSanitizerScript().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => { syncCsvDynamicRules().catch(() => {}); syncSanitizerScript().catch(() => {}); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.blockedCsvSources) syncCsvDynamicRules().catch(() => {});
});

async function getBackendUrl() {
  const { backendUrl } = await chrome.storage.local.get("backendUrl");
  if (!backendUrl) throw new Error("Set your PhishGuard backend URL in the extension popup first.");
  const base = backendUrl.replace(/\/+$/, "");
  return base.replace(/\/api$/i, "");
}
async function requestJson(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    let response;
    try {
      response = await fetch(url, { ...options, signal: controller.signal, cache: "no-store" });
    } catch (error) {
      const message = error?.message || "Network request failed";
      if (/failed to fetch|networkerror|load failed/i.test(message)) {
        throw new Error("Cannot reach the PhishGuard backend. Check its URL, make sure it is running/deployed, and click Save & authorize backend again.");
      }
      throw error;
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data?.error || `HTTP ${response.status}`;
      if (response.status === 404) throw new Error(`API route not found at ${url}. Deploy the matching PhishGuard backend and check the backend URL.`);
      if (response.status === 401 || response.status === 403) throw new Error(`Backend/provider access denied (${response.status}). Check backend permissions and provider API configuration.`);
      throw new Error(`PhishGuard backend: ${detail}`);
    }
    return data;
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("PhishGuard backend timed out. Try again.");
    throw error;
  } finally { clearTimeout(timeout); }
}
async function analyze(payload) {
  const base = await getBackendUrl();
  return requestJson(base + "/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
}
function assessUrlReport(data) {
  const urlItems = Array.isArray(data.urls) ? data.urls : [];
  const checks = urlItems.flatMap(u => Array.isArray(u.checks) ? u.checks : []);
  const checkText = c => `${c.provider || ""} ${c.status || ""} ${c.detail || ""}`.toLowerCase();
  const threat = checks.some(c => /threat match|malicious detections|flagged .* as malicious|phishing|malware detected/.test(checkText(c))) || data.score >= 50;
  const suspicious = checks.some(c => /suspicious detections|flagged .* as suspicious/.test(checkText(c))) || data.score >= 25;
  const meaningfulClean = checks.some(c =>
    (/google safe browsing/.test(checkText(c)) && /no match returned/.test(checkText(c))) ||
    (/virustotal/.test(checkText(c)) && /\b0 malicious\b/.test(checkText(c)) && /\b0 suspicious\b/.test(checkText(c)))
  );
  const providerResponded = checks.some(c =>
    (/google safe browsing/.test(checkText(c)) && /no match returned|threat match/.test(checkText(c))) ||
    (/virustotal/.test(checkText(c)) && /\d+ malicious/.test(checkText(c)))
  );
  let status = "inconclusive";
  if (threat) status = "danger";
  else if (suspicious) status = "caution";
  else if (meaningfulClean) status = "no_threat_detected";
  else if (!providerResponded) status = "inconclusive";
  return { ok: true, status, score: Number(data.score) || 0, level: data.level || "Unknown", summary: data.summary || "", findings: data.findings || [], checks, hasLive: providerResponded, simulated: !providerResponded, urlsFound: urlItems.length };
}
async function checkUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(String(rawUrl || "")); } catch { throw new Error("Invalid URL."); }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS links can be checked.");
  const csvDecision = await findCsvDecision(parsed.href);
  if (csvDecision?.decision === "block") {
    return { ok: true, status: "danger", score: 100, level: "Critical", summary: csvDecision.reason, findings: [{ title: "Blocked by CSV rule", detail: `Matched source: ${csvDecision.source}` }], checks: [], hasLive: true, source: "csv" };
  }
  const base = await getBackendUrl();
  const data = await requestJson(base + "/api/check-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: parsed.href }) });
  const report = assessUrlReport(data);
  if (csvDecision?.decision === "allow") report.csvAllowRule = csvDecision.source;
  return report;
}
async function getAttachmentStatus(analysisId) {
  const base = await getBackendUrl();
  const data = await requestJson(base + "/api/analyze-attachment/status?id=" + encodeURIComponent(String(analysisId || "")));
  return data;
}
async function analyzeAttachment(message) {
  const base = await getBackendUrl();
  const binary = atob(String(message.base64 || ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (!bytes.length) throw new Error("Attachment is empty.");
  if (bytes.length > 10 * 1024 * 1024) throw new Error("Attachment exceeds the 10 MB limit.");
  const form = new FormData();
  const name = String(message.fileName || "attachment.bin").replace(/[\\/\0]/g, "_").slice(0, 180);
  form.append("file", new Blob([bytes], { type: message.mimeType || "application/octet-stream" }), name);
  return requestJson(base + "/api/analyze-attachment", { method: "POST", body: form });
}

const SANITIZER_SCRIPT_ID = "phishguard-url-sanitizer";
const ALL_WEB_ORIGINS = ["http://*/*", "https://*/*"];

async function syncSanitizerScript() {
  const data = await chrome.storage.local.get("urlSanitizationEnabled");
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [SANITIZER_SCRIPT_ID] }).catch(() => []);
  if (registered.length) await chrome.scripting.unregisterContentScripts({ ids: [SANITIZER_SCRIPT_ID] }).catch(() => {});
  if (data.urlSanitizationEnabled !== true) return { ok: true, enabled: false };
  const granted = await chrome.permissions.contains({ origins: ALL_WEB_ORIGINS });
  if (!granted) return { ok: false, enabled: false, error: "Site access is not granted. Enable URL sanitization from the dashboard and approve site access." };
  await chrome.scripting.registerContentScripts([{
    id: SANITIZER_SCRIPT_ID,
    matches: ALL_WEB_ORIGINS,
    js: ["content/url-sanitizer.js"],
    runAt: "document_start",
    allFrames: false,
    persistAcrossSessions: true
  }]);
  return { ok: true, enabled: true };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_SYNC_CSV_RULES") { syncCsvDynamicRules().then(() => sendResponse({ ok: true })).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_SYNC_SANITIZER") { syncSanitizerScript().then(sendResponse).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_ANALYZE_ATTACHMENT") { analyzeAttachment(message).then(data => sendResponse({ ok: true, data })).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_ATTACHMENT_STATUS") { getAttachmentStatus(message.analysisId).then(data => sendResponse({ ok: true, data })).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_ANALYZE") { analyze(message.payload || {}).then(data => sendResponse({ ok: true, data })).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_CHECK_URL") { checkUrl(message.url).then(data => sendResponse(data)).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_HEALTH") { getBackendUrl().then(base => requestJson(base + "/api/health")).then(data => sendResponse({ ok: true, data })).catch(error => sendResponse({ ok: false, error: error.message })); return true; }
  if (message?.type === "PHISHGUARD_OPEN_URL") {
    try { const u = new URL(String(message.url || "")); if (!["http:", "https:"].includes(u.protocol)) throw new Error("Unsupported URL"); chrome.tabs.create({ url: u.href, active: true }, tab => sendResponse({ ok: !chrome.runtime.lastError, tabId: tab?.id, error: chrome.runtime.lastError?.message })); }
    catch (error) { sendResponse({ ok: false, error: error.message }); }
    return true;
  }
});
