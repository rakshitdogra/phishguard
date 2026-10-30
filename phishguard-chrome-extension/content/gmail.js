(() => {
  if (window.__phishGuardGmailLoaded) return;
  window.__phishGuardGmailLoaded = true;

  const BTN_ID = "phishguard-gmail-scan-button";
  const PANEL_ID = "phishguard-gmail-result";
  const MAX_BODY_CHARS = 45000;
  const UI_WORDS = new Set([
    "download", "add to drive", "edit with", "scanning for viruses...",
    "scanning for viruses", "preview", "preview attachment", "remove",
    "print", "reply", "forward", "more", "show details", "hide details"
  ]);
  const FILE_EXT = /\.(?:pdf|docx?|xlsx?|pptx?|csv|txt|rtf|odt|ods|odp|zip|rar|7z|tar|gz|eml|msg|html?|svg|png|jpe?g|gif|webp|mp[34]|wav|exe|msi|js|jar|apk|dmg|iso|one|docm|xlsm|pptm)$/i;

  function isVisible(el) {
    if (!el || !el.isConnected) return false;
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" &&
      Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
  }

  function currentMessageBody() {
    // Gmail may keep collapsed messages in the DOM. Prefer the last visible body,
    // which usually corresponds to the message the user just opened.
    const candidates = [...document.querySelectorAll(".a3s")].filter(isVisible);
    return candidates[candidates.length - 1] || null;
  }

  function getMessageContainer(bodyNode) {
    return bodyNode?.closest(".adn") ||
      bodyNode?.closest("[data-message-id]") ||
      bodyNode?.parentElement?.parentElement ||
      document;
  }

  function cleanText(value) {
    return String(value || "").replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
  }

  function extractAttachmentNames(container) {
    if (!container) return [];
    const candidates = new Set();

    // Read candidate names only from likely attachment cards, never all Gmail spans.
    const selectors = [
      ".aQH .aZo", ".aQH .aV3", ".aQH [download_url]",
      ".aQH [data-tooltip]", ".aQH [aria-label]",
      ".aQH .aV3", ".aQH .aQy"
    ];
    for (const selector of selectors) {
      container.querySelectorAll(selector).forEach(el => {
        const raw = [
          el.getAttribute("download_url"),
          el.getAttribute("data-tooltip"),
          el.getAttribute("aria-label"),
          el.getAttribute("title"),
          el.innerText,
          el.textContent
        ].map(cleanText).filter(Boolean);
        raw.forEach(text => candidates.add(text));
      });
    }

    const names = new Set();
    for (let text of candidates) {
      // Gmail labels sometimes prepend "Preview attachment".
      text = text.replace(/^preview attachment\s*/i, "").trim();
      // Strip file size suffixes, but only after a recognizable filename.
      const sizeMatch = text.match(/^(.+?\.[a-z0-9]{1,8})\s+\d+(?:\.\d+)?\s*(?:bytes?|kb|mb|gb)\b/i);
      if (sizeMatch) text = sizeMatch[1].trim();
      // Ignore toolbar labels, progress messages, sizes, and empty/generic labels.
      if (!text || UI_WORDS.has(text.toLowerCase())) continue;
      if (/^(?:scanning|virus scan|download|add to drive|edit with)\b/i.test(text)) continue;
      if (/^\d+(?:\.\d+)?\s*(?:bytes?|kb|mb|gb)$/i.test(text)) continue;
      if (text.length > 220 || /[\r\n]/.test(text)) continue;

      // Only accept names with a plausible filename extension. This avoids
      // turning Gmail's UI labels into attachment indicators.
      const filename = text.match(/(?:^|[\s:])([^\s:<>|?*"]+\.[a-z0-9]{1,8})(?:$|\s)/i);
      if (!filename || !FILE_EXT.test(filename[1])) continue;
      const name = filename[1].replace(/^["']|["']$/g, "");
      if (UI_WORDS.has(name.toLowerCase())) continue;
      names.add(name);
    }
    return [...names].slice(0, 20);
  }

  function extractAttachmentLinks(container) {
    if (!container) return [];
    const found = new Map();
    // Gmail's attachment download/preview URLs usually carry attid plus view=att.
    // Only collect URLs inside the currently open message's attachment area.
    const areas = [...container.querySelectorAll('.aQH, [data-attachment-id], [data-tooltip*="Download"]')];
    for (const area of areas) {
      for (const a of area.querySelectorAll('a[href]')) {
        try {
          const u = new URL(a.href, location.href);
          if (u.origin !== location.origin || !/mail\.google\.com$/.test(u.hostname)) continue;
          if (!(u.searchParams.has('attid') || /view=att|disp=attd/i.test(u.href))) continue;
          const name = cleanText(a.getAttribute('download') || a.getAttribute('aria-label') || a.getAttribute('data-tooltip') || a.innerText || a.textContent);
          if (!name || !FILE_EXT.test(name)) continue;
          found.set(u.href, {url:u.href, name:name.slice(0,180)});
        } catch { /* Ignore malformed links. */ }
      }
    }
    return [...found.values()].slice(0, 3);
  }

  function extractLinks(bodyNode) {
    if (!bodyNode) return [];
    const links = new Set();
    bodyNode.querySelectorAll("a[href]").forEach(a => {
      try {
        const url = new URL(a.getAttribute("href"), location.href);
        if (["http:", "https:"].includes(url.protocol) && url.hostname &&
            !url.hostname.endsWith("googleusercontent.com") &&
            !url.hostname.endsWith("mail.google.com")) {
          links.add(url.href);
        }
      } catch { /* Ignore malformed or non-web hrefs. */ }
    });
    return [...links].slice(0, 50);
  }

  function currentEmail() {
    const bodyNode = currentMessageBody();
    const container = getMessageContainer(bodyNode);
    const subjectNode = document.querySelector("h2.hP") ||
      document.querySelector("h2[data-thread-perm-id]");
    const subject = cleanText(subjectNode?.innerText || "");

    // Scope sender selection to the visible message when possible.
    const senderNodes = [...container.querySelectorAll?.(".gD[email]") || []].filter(isVisible);
    const senderNode = senderNodes[senderNodes.length - 1] ||
      [...document.querySelectorAll(".gD[email]")].filter(isVisible).slice(-1)[0];
    const sender = senderNode?.getAttribute("email") || "";
    const displayName = senderNode?.getAttribute("name") || cleanText(senderNode?.innerText || "");
    let body = cleanText(bodyNode?.innerText || "");

    // Many emails use linked display text (e.g. "Click here") instead of printing
    // the URL. Add actual hrefs from the message body so the backend can inspect them.
    const links = extractLinks(bodyNode);
    if (links.length) body += "\n\nLinks extracted from message HTML:\n" + links.join("\n");
    body = body.slice(0, MAX_BODY_CHARS);

    const attachmentLinks = extractAttachmentLinks(container);
    const attachments = [...new Set([...extractAttachmentNames(container), ...attachmentLinks.map(a => a.name)])].join("\n");
    return {sender, displayName, subject, body, attachments, attachmentLinks, headers:""};
  }

  function makePanel() {
    let panel = document.getElementById(PANEL_ID);
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = PANEL_ID;
    Object.assign(panel.style, {
      position:"fixed", right:"18px", bottom:"76px", zIndex:"2147483647",
      width:"340px", maxWidth:"calc(100vw - 28px)", maxHeight:"62vh",
      overflow:"auto", background:"#fff", color:"#182230",
      border:"1px solid #d9e0eb", borderRadius:"14px",
      boxShadow:"0 12px 36px #0002", padding:"14px",
      font:"13px/1.45 system-ui,sans-serif"
    });
    const close = document.createElement("button");
    close.textContent = "Close";
    close.type = "button";
    Object.assign(close.style, {float:"right", border:"0", background:"#edf1f8", borderRadius:"6px", padding:"5px 8px", cursor:"pointer"});
    close.addEventListener("click", () => panel.remove());
    const title = document.createElement("strong");
    title.textContent = "PhishGuard email scan";
    const content = document.createElement("div");
    content.className = "phishguard-content";
    content.style.marginTop = "12px";
    panel.append(close, title, content);
    document.body.append(panel);
    return panel;
  }

  function addText(parent, tag, text, css) {
    const el = document.createElement(tag);
    el.textContent = String(text ?? "");
    if (css) el.style.cssText = css;
    parent.append(el);
    return el;
  }

  function renderReport(out, report, submitted) {
    out.replaceChildren();
    const score = Number.isFinite(Number(report.score)) ? Number(report.score) : null;
    const level = report.level || "Unknown";
    addText(out, "div", score === null ? `${level} · score unavailable` : `${level} risk · ${score}/100`,
      "font-weight:800;font-size:18px;margin-bottom:7px;color:" +
      (score >= 50 ? "#b42318" : score >= 25 ? "#9a6700" : "#16794b"));
    addText(out, "p", report.summary || "Review the findings below.", "margin:4px 0 9px");

    const findings = Array.isArray(report.findings) ? report.findings.slice(0, 10) : [];
    addText(out, "strong", `Findings (${findings.length}${report.findings?.length > findings.length ? "+" : ""})`, "display:block;margin:10px 0 5px");
    if (!findings.length) addText(out, "p", "No suspicious indicators were found in the supplied message.", "font-size:12px;color:#687588");
    findings.forEach(f => {
      const color = f.severity === "bad" ? "#b42318" : f.severity === "warn" ? "#9a6700" : f.severity === "good" ? "#16794b" : "#475467";
      addText(out, "p", `• ${f.title || "Finding"}: ${f.detail || ""}`,
        `margin:6px 0;color:${color};overflow-wrap:anywhere`);
    });

    if (Array.isArray(report.urls) && report.urls.length) {
      addText(out, "strong", "URL reputation", "display:block;margin:12px 0 5px");
      report.urls.slice(0, 10).forEach(item => {
        addText(out, "p", `${item.domain || item.url}: ${
          (item.checks || []).map(c => `${c.provider} — ${c.status}`).join("; ") || "No provider result"
        }`, "margin:5px 0;font-size:11px;overflow-wrap:anywhere");
      });
    }

    if (report.auth && Object.keys(report.auth).length) {
      addText(out, "strong", "Email authentication", "display:block;margin:12px 0 5px");
      addText(out, "p", Object.entries(report.auth).map(([k,v]) => `${k.toUpperCase()}: ${v || "not provided"}`).join(" · "),
        "font-size:11px;color:#475467");
    } else {
      // Gmail visible-message view does not expose raw authentication headers; omit this detail from the compact report.
    }

    if (Array.isArray(report.actions) && report.actions.length) {
      addText(out, "strong", "Recommended actions", "display:block;margin:12px 0 5px");
      const ul = document.createElement("ul");
      ul.style.cssText = "padding-left:18px;margin:4px 0";
      report.actions.slice(0, 5).forEach(action => addText(ul, "li", action, "margin:5px 0"));
      out.append(ul);
    }

    addText(out, "p", `Submitted fields: sender ${submitted.sender ? "found" : "not found"} · subject ${submitted.subject ? "found" : "not found"} · body ${submitted.body.length} characters · attachment filenames ${submitted.attachments ? submitted.attachments.split("\n").length : 0}.`,
      "font-size:10px;color:#687588;border-top:1px solid #e4e8ef;padding-top:8px;margin-top:10px");
  }

  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

  async function scanAttachmentFiles(attachmentLinks, out) {
    if (!attachmentLinks?.length) return [];
    addText(out, "strong", "Attachment scan", "display:block;margin:12px 0 5px");
    const results = [];
    for (const item of attachmentLinks.slice(0, 3)) {
      const row = addText(out, "p", `${item.name}: Scanning…`, "font-size:12px;color:#475467;overflow-wrap:anywhere;margin:6px 0");
      try {
        const response = await fetch(item.url, { credentials: "include", cache: "no-store" });
        if (!response.ok) throw new Error("Attachment unavailable");
        const blob = await response.blob();
        if (!blob.size) throw new Error("Empty attachment");
        if (blob.size > 10 * 1024 * 1024) throw new Error("File exceeds the 10 MB scan limit");
        const bytes = new Uint8Array(await blob.arrayBuffer());
        let binary = "";
        for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        const result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_ANALYZE_ATTACHMENT", fileName: item.name, mimeType: blob.type || "application/octet-stream", base64: btoa(binary) });
        if (!result?.ok) throw new Error(result?.error || "Scan unavailable");
        let data = result.data || {};
        if (data.analysisId) {
          row.textContent = `${item.name}: Scanning…`;
          for (let attempt = 0; attempt < 8; attempt++) {
            await wait(2000);
            const statusResponse = await chrome.runtime.sendMessage({ type: "PHISHGUARD_ATTACHMENT_STATUS", analysisId: data.analysisId });
            if (!statusResponse?.ok) break;
            if (statusResponse.data?.completed) { data = { ...data, ...statusResponse.data }; break; }
          }
        }
        const stats = data.stats || data.data?.attributes?.last_analysis_stats || {};
        const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
        let verdict = data.status || "Unable to determine";
        if (malicious > 0 || /malicious|infected/i.test(verdict)) verdict = "Malicious";
        else if (suspicious > 0 || /suspicious/i.test(verdict)) verdict = "Suspicious";
        else if (/no known threat detected/i.test(verdict) || (data.completed && malicious === 0 && suspicious === 0)) verdict = "No threat detected";
        else if (/submitted|queued|in progress/i.test(verdict)) verdict = "Still scanning…";
        else if (/unknown file|inconclusive|offline mode/i.test(verdict)) verdict = "Unable to determine";
        row.textContent = `${item.name}: ${verdict}`;
        row.style.color = /malicious/i.test(verdict) ? "#b42318" : /suspicious|unable|still scanning/i.test(verdict) ? "#9a6700" : "#16794b";
        results.push({ name: item.name, data });
      } catch (e) {
        row.textContent = `${item.name}: Unable to scan`;
        row.style.color = "#9a6700";
        results.push({ name: item.name, error: e.message || "Unable to scan" });
      }
    }
    return results;
  }

  function addButton() {
    if (document.getElementById(BTN_ID) || !document.body) return;
    const btn = document.createElement("button");
    btn.id = BTN_ID;
    btn.type = "button";
    btn.textContent = "Scan with PhishGuard";
    Object.assign(btn.style, {
      position:"fixed", right:"18px", bottom:"18px", zIndex:"2147483647",
      border:"0", borderRadius:"10px", padding:"12px 15px", background:"#285de8",
      color:"#fff", font:"600 13px system-ui,sans-serif",
      boxShadow:"0 5px 18px #0002", cursor:"pointer"
    });
    btn.addEventListener("click", async () => {
      const panel = makePanel(), out = panel.querySelector(".phishguard-content");
      out.textContent = "Analyzing the currently open message…";
      const email = currentEmail();
      if (!email.body && !email.subject && !email.sender) {
        out.textContent = "Open an email message in Gmail first. PhishGuard only scans after you click this button.";
        return;
      }
      btn.disabled = true;
      try {
        const result = await chrome.runtime.sendMessage({type:"PHISHGUARD_ANALYZE", payload:email});
        if (!result?.ok) throw new Error(result?.error || "Analysis failed.");
        renderReport(out, result.data, email);
        await scanAttachmentFiles(email.attachmentLinks, out);
      } catch (e) {
        out.textContent = e.message || "Could not reach PhishGuard backend.";
      } finally { btn.disabled = false; }
    });
    document.body.append(btn);
  }

  const observer = new MutationObserver(() => addButton());
  observer.observe(document.documentElement, {childList:true, subtree:true});
  addButton();
})();