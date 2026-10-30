const $ = id => document.getElementById(id);
const STORAGE_KEY = "blockedCsvSources";
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_ROWS_PER_SOURCE = 4500;
const MAX_TOTAL_RULES = 4500;

function parseCsv(text) {
  const rows = [];
  let row = [], cell = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"' && cell.length === 0) quoted = true;
    else if (ch === ',') { row.push(cell.trim()); cell = ""; }
    else if (ch === '\n') { row.push(cell.trim()); if (row.some(v => v !== "")) rows.push(row); row = []; cell = ""; }
    else if (ch !== '\r') cell += ch;
  }
  if (quoted) throw new Error("CSV contains an unclosed quoted field.");
  row.push(cell.trim()); if (row.some(v => v !== "")) rows.push(row);
  return rows;
}
function cleanUrl(value) {
  const raw = String(value || "").trim();
  let candidate = raw;
  if (!/^https?:\/\//i.test(candidate)) candidate = "https://" + candidate;
  const u = new URL(candidate);
  if (!['http:', 'https:'].includes(u.protocol) || !u.hostname || u.username || u.password) throw new Error(`Invalid link: ${value}`);
  return u.href;
}
function convertCsv(text, sourceName, mode) {
  const rows = parseCsv(text);
  if (!rows.length) throw new Error("CSV is empty.");
  const first = String(rows[0][0] || "").replace(/^\uFEFF/, "").trim().toLowerCase();
  const hasHeader = ["link", "links", "url", "website", "website_url"].includes(first);
  const dataRows = hasHeader ? rows.slice(1) : rows;
  if (!dataRows.length) throw new Error("CSV needs at least one link.");
  if (!['whitelist', 'blacklist'].includes(mode)) throw new Error("Choose whitelist or blacklist for this CSV source.");
  const entries = [];
  for (let i = 0; i < dataRows.length; i++) {
    const cells = dataRows[i];
    const nonempty = cells.map(v => String(v || "").trim()).filter(Boolean);
    if (!nonempty.length) continue;
    if (nonempty.length !== 1) throw new Error(`Row ${i + (hasHeader ? 2 : 1)} must contain exactly one link. CSV files should have only one column.`);
    const value = cleanUrl(nonempty[0]);
    entries.push({ type: "url", value, action: mode === "whitelist" ? "allow" : "block", enabled: true, row: i + (hasHeader ? 2 : 1) });
    if (entries.length > MAX_ROWS_PER_SOURCE) throw new Error(`A CSV source can contain at most ${MAX_ROWS_PER_SOURCE} links.`);
  }
  if (!entries.length) throw new Error("No valid links were found in this CSV.");
  return { id: crypto.randomUUID(), name: sourceName, mode, enabled: true, addedAt: new Date().toISOString(), entries };
}
function matches(entry, rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (entry.type === "domain") return u.hostname.toLowerCase() === entry.value || u.hostname.toLowerCase().endsWith("." + entry.value);
    if (entry.type === "url") { try { return u.href === new URL(entry.value).href; } catch { return false; } }
    if (entry.type === "pattern") {
      const m = entry.value.match(/^\|\|([a-z0-9.-]+)\^$/i);
      if (m) return u.hostname.toLowerCase() === m[1].toLowerCase() || u.hostname.toLowerCase().endsWith("." + m[1].toLowerCase());
      return u.href.toLowerCase().includes(entry.value.toLowerCase());
    }
  } catch {}
  return false;
}
async function getSources() {
  const data = await chrome.storage.local.get(STORAGE_KEY);
  return Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
}
async function saveSources(sources) {
  await chrome.storage.local.set({ [STORAGE_KEY]: sources });
  await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_CSV_RULES" }).catch(() => {});
  renderSources();
}
function setStatus(id, message, type = "") {
  const el = $(id); el.textContent = message; el.className = `status ${type}`.trim();
}
async function renderSources() {
  const [sources, data] = await Promise.all([getSources(), chrome.storage.local.get("csvBlockingEnabled")]);
  const list = $("sourceList"); list.replaceChildren();
  const count = sources.reduce((n, s) => n + (Array.isArray(s.entries) ? s.entries.length : 0), 0);
  $("sourceCount").textContent = `${sources.length} source${sources.length === 1 ? "" : "s"} · ${count} rules`;
  $("toggleBlocking").textContent = data.csvBlockingEnabled ? "Disable CSV blocking" : "Enable CSV blocking";
  $("blockingStatus").textContent = data.csvBlockingEnabled ? "CSV blocking is enabled. Matching website navigations are blocked locally." : "CSV rules are saved but not actively blocking website navigation.";
  $("blockingStatus").className = "status " + (data.csvBlockingEnabled ? "success" : "");
  if (!sources.length) { const empty = document.createElement("div"); empty.className = "empty"; empty.textContent = "Import a CSV to add your first source."; list.append(empty); return; }
  sources.forEach(source => {
    const card = document.createElement("article"); card.className = "source";
    const info = document.createElement("div"); const title = document.createElement("h3"); title.textContent = source.name; const meta = document.createElement("div"); meta.className = "meta"; meta.textContent = `${source.entries?.length || 0} links · ${(source.mode || "blacklist").toUpperCase()} · ${source.enabled === false ? "Disabled source" : "Enabled source"}`; info.append(title, meta);
    const actions = document.createElement("div"); actions.className = "actions";
    const modeSelect = document.createElement("select"); modeSelect.className = "source-mode";
    modeSelect.setAttribute("aria-label", `List type for ${source.name}`);
    modeSelect.innerHTML = '<option value="blacklist">Blacklist</option><option value="whitelist">Whitelist</option>';
    modeSelect.value = source.mode === "whitelist" ? "whitelist" : "blacklist";
    modeSelect.addEventListener("change", async () => { const all = await getSources(); const target = all.find(s => s.id === source.id); if (target) { target.mode = modeSelect.value; for (const entry of (target.entries || [])) entry.action = target.mode === "whitelist" ? "allow" : "block"; await saveSources(all); setStatus("importStatus", `${target.name} set to ${target.mode}.`, "success"); } });
    const label = document.createElement("label"); label.className = "toggle"; const check = document.createElement("input"); check.type = "checkbox"; check.checked = source.enabled !== false; check.addEventListener("change", async () => { const all = await getSources(); const target = all.find(s => s.id === source.id); if (target) target.enabled = check.checked; await saveSources(all); }); label.append(check, document.createTextNode("Enabled"));
    const remove = document.createElement("button"); remove.className = "secondary"; remove.textContent = "Remove"; remove.addEventListener("click", async () => { if (!confirm(`Remove CSV source “${source.name}”?`)) return; await saveSources((await getSources()).filter(s => s.id !== source.id)); setStatus("importStatus", `Removed ${source.name}.`, "success"); });
    actions.append(modeSelect, label, remove); card.append(info, actions); list.append(card);
  });
}
$("csvFiles").addEventListener("change", async event => {
  const files = Array.from(event.target.files || []); if (!files.length) return;
  setStatus("importStatus", "Reading CSV files locally…");
  const sources = await getSources(); const errors = [], added = [];
  let totalRules = sources.reduce((total, source) => total + (Array.isArray(source.entries) ? source.entries.length : 0), 0);
  for (const file of files) {
    try {
      if (!file.name.toLowerCase().endsWith(".csv") && file.type !== "text/csv") throw new Error("Choose a .csv file.");
      if (file.size > MAX_FILE_BYTES) throw new Error("File exceeds the 5 MB limit.");
      const source = convertCsv(await file.text(), file.name, $("importMode").value);
      if (totalRules + source.entries.length > MAX_TOTAL_RULES) throw new Error(`The extension supports up to ${MAX_TOTAL_RULES} combined CSV rules. Remove a source or import a smaller list first.`);
      if (sources.some(s => String(s.name || "").toLowerCase() === source.name.toLowerCase())) source.name = `${file.name} (${new Date().toLocaleString()})`;
      sources.push(source); totalRules += source.entries.length; added.push(`${source.name} (${source.entries.length} rules)`);
    } catch (error) { errors.push(`${file.name}: ${error.message}`); }
  }
  if (added.length) {
    try { await saveSources(sources); }
    catch (error) { errors.push(error.message || "Could not save CSV sources."); }
  }
  setStatus("importStatus", [...(added.length ? [`Imported ${added.join(", ")}. List type: ${$("importMode").value}.`] : []), ...errors].join(" ") || "No files imported.", errors.length ? "error" : added.length ? "success" : "");
  event.target.value = "";
});
$("toggleBlocking").addEventListener("click", async () => {
  const button = $("toggleBlocking"); button.disabled = true;
  try {
    const data = await chrome.storage.local.get("csvBlockingEnabled");
    if (data.csvBlockingEnabled) {
      await chrome.storage.local.set({ csvBlockingEnabled: false });
      const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_CSV_RULES" });
      if (!result?.ok) throw new Error(result?.error || "Could not disable CSV rules.");
      setStatus("blockingStatus", "CSV blocking disabled. Your imported sources are preserved.", "success");
    } else {
      const granted = await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] });
      if (!granted) throw new Error("Chrome site access was not granted. CSV rules are saved but won't block navigations.");
      await chrome.storage.local.set({ csvBlockingEnabled: true });
      const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_CSV_RULES" });
      if (!result?.ok) {
        await chrome.storage.local.set({ csvBlockingEnabled: false });
        await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_CSV_RULES" }).catch(() => {});
        throw new Error(result?.error || "Could not apply CSV rules.");
      }
      setStatus("blockingStatus", "CSV blocking enabled. Matching website navigations will be blocked.", "success");
    }
    await renderSources();
  } catch (error) { setStatus("blockingStatus", error.message || "Could not change blocking state.", "error"); }
  finally { button.disabled = false; }
});
$("refreshRules").addEventListener("click", async () => {
  try { const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_CSV_RULES" }); if (!result?.ok) throw new Error(result?.error || "Could not refresh rules."); setStatus("importStatus", "Chrome blocking rules refreshed.", "success"); }
  catch (error) { setStatus("importStatus", error.message, "error"); }
});
$("testForm").addEventListener("submit", async event => {
  event.preventDefault(); const url = $("testUrl").value.trim(); const out = $("testResult"); out.className = "test-result"; out.textContent = "Checking local CSV sources…";
  try {
    const parsed = new URL(url); if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs can be tested.");
    const sources = await getSources(); const matchesFound = [];
    for (const source of sources) { if (source.enabled === false) continue; for (const entry of source.entries || []) if (entry.enabled !== false && matches(entry, parsed.href)) matchesFound.push({ source, entry }); }
    const allow = matchesFound.find(m => (m.source.mode || (m.entry.action === "allow" ? "whitelist" : "blacklist")) === "whitelist");
    const block = matchesFound.find(m => (m.source.mode || (m.entry.action === "allow" ? "whitelist" : "blacklist")) === "blacklist");
    if (allow) { out.className = "test-result allow"; out.textContent = `WHITELIST MATCH: allowed by ${allow.source.name}.`; }
    else if (block) { out.className = "test-result block"; out.textContent = `BLACKLIST MATCH: blocked by ${block.source.name}.`; }
    else { out.className = "test-result none"; out.textContent = "No match in enabled CSV sources. Backend reputation checks are separate."; }
  } catch (error) { out.className = "test-result block"; out.textContent = error.message || "Could not test this URL."; }
});
async function renderSanitizationSettings() {
  const data = await chrome.storage.local.get(["urlSanitizationEnabled", "urlSanitizationWhitelist"]);
  $("toggleSanitization").textContent = data.urlSanitizationEnabled ? "Disable URL sanitization" : "Enable URL sanitization";
  $("sanitizationStatus").textContent = data.urlSanitizationEnabled ? "URL sanitization is enabled for sites where Chrome grants access." : "URL sanitization is disabled.";
  $("sanitizationStatus").className = "status " + (data.urlSanitizationEnabled ? "success" : "");
  $("sanitizationWhitelist").value = (Array.isArray(data.urlSanitizationWhitelist) ? data.urlSanitizationWhitelist : []).join("\n");
}
function normalizeWhitelist(text) {
  const lines = String(text || "").split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const output = [];
  for (const line of lines) {
    const host = line.toLowerCase().replace(/^https?:\/\//, "").split(/[/?#:]/)[0].replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
    if (!host || host.length > 253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(host)) throw new Error(`Invalid domain: ${line}`);
    if (!output.includes(host)) output.push(host);
    if (output.length > 500) throw new Error("A maximum of 500 sanitization exceptions is allowed.");
  }
  return output;
}
$("toggleSanitization").addEventListener("click", async () => {
  const button = $("toggleSanitization"); button.disabled = true;
  try {
    const isEnabled = button.textContent.trim().toLowerCase().startsWith("disable");
    if (isEnabled) {
      await chrome.storage.local.set({ urlSanitizationEnabled: false });
      const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_SANITIZER" });
      if (!result?.ok) throw new Error(result?.error || "Could not disable URL sanitization.");
      setStatus("sanitizationStatus", "URL sanitization disabled.", "success");
    } else {
      const granted = await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] });
      if (!granted) throw new Error("Chrome site access was not granted. URL sanitization remains disabled.");
      await chrome.storage.local.set({ urlSanitizationEnabled: true });
      const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SYNC_SANITIZER" });
      if (!result?.ok) { await chrome.storage.local.set({ urlSanitizationEnabled: false }); throw new Error(result?.error || "Could not enable URL sanitization."); }
      setStatus("sanitizationStatus", "URL sanitization enabled. Refresh already-open tabs to activate it there.", "success");
    }
    await renderSanitizationSettings();
  } catch (error) { setStatus("sanitizationStatus", error.message || "Could not change URL sanitization.", "error"); }
  finally { button.disabled = false; }
});
$("saveSanitizationWhitelist").addEventListener("click", async () => {
  try {
    const domains = normalizeWhitelist($("sanitizationWhitelist").value);
    await chrome.storage.local.set({ urlSanitizationWhitelist: domains });
    setStatus("whitelistStatus", `Saved ${domains.length} sanitization exception${domains.length === 1 ? "" : "s"}.`, "success");
  } catch (error) { setStatus("whitelistStatus", error.message || "Could not save exceptions.", "error"); }
});
renderSources();
renderSanitizationSettings();
