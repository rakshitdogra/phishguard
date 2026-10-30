(() => {
  if (window.__phishGuardUrlSanitizerInstalled) return;
  window.__phishGuardUrlSanitizerInstalled = true;

  const TRACKING_KEYS = new Set([
    "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "twclid", "ttclid",
    "igshid", "yclid", "srsltid", "mc_cid", "mc_eid", "mkt_tok", "oly_anon_id",
    "oly_enc_id", "vero_id", "vero_conv", "wickedid", "rb_clickid", "epik", " ScCid".trim().toLowerCase(),
    "_ga", "_gl", "_gac", "_hsenc", "_hsmi", "_kx", "_ke", "ref_src", "ref_url",
    "campaign_id", "ad_id", "adset_id", "campaign", "campaignid", "tracking_id"
  ]);
  const TRACKING_PREFIXES = ["utm_", "pk_", "mtm_", "matomo_", "vero_"];
  const PRESERVE_PATTERNS = [
    /(^|[_-])(token|auth|authorization|signature|sig|key|secret|code|state|nonce|session|sid|jwt|password|pass|credential|expires|expiry)([_-]|$)/i,
    /^x-amz-/i, /^x-goog-/i, /^awsaccesskeyid$/i, /^googleaccessid$/i, /^response-content-/i
  ];

  function shouldPreserve(key) {
    return PRESERVE_PATTERNS.some(pattern => pattern.test(key));
  }
  function sanitizeUrl(raw) {
    let url;
    try { url = new URL(raw, location.href); } catch { return null; }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password) return null;
    let changed = false;
    for (const key of Array.from(url.searchParams.keys())) {
      const lower = key.toLowerCase();
      if (shouldPreserve(key)) continue;
      if (TRACKING_KEYS.has(lower) || TRACKING_PREFIXES.some(prefix => lower.startsWith(prefix))) {
        url.searchParams.delete(key);
        changed = true;
      }
    }
    // Common fragment-based analytics tags; leave ordinary fragments and SPA routes intact.
    if (url.hash && /^#(?:utm_[^=]+|gclid|fbclid|mc_cid|mc_eid)=/i.test(url.hash)) {
      url.hash = "";
      changed = true;
    }
    return { href: url.href, changed };
  }
  function hostMatches(host, rule) {
    const normalized = String(rule || "").trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#:]/)[0].replace(/^\*\./, "").replace(/^\.+|\.+$/g, "");
    return !!normalized && (host === normalized || host.endsWith("." + normalized));
  }
  let whitelist = [];
  let refreshId = 0;
  function refreshWhitelist() {
    const id = ++refreshId;
    chrome.storage.local.get({ urlSanitizationWhitelist: [] }, data => {
      if (chrome.runtime.lastError || id !== refreshId) return;
      whitelist = Array.isArray(data.urlSanitizationWhitelist) ? data.urlSanitizationWhitelist : [];
    });
  }
  refreshWhitelist();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.urlSanitizationWhitelist) refreshWhitelist();
  });

  function findAnchor(event) {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
    for (const node of path) {
      if (node instanceof HTMLAnchorElement) return node;
      if (node && node.nodeType === Node.ELEMENT_NODE && typeof node.closest === "function") {
        const anchor = node.closest("a[href]");
        if (anchor) return anchor;
      }
    }
    return null;
  }
  function sanitizeAnchor(event) {
    if (!event.isTrusted) return;
    const anchor = findAnchor(event);
    if (!anchor || !anchor.href) return;
    let target;
    try { target = new URL(anchor.href); } catch { return; }
    if (!/^https?:$/.test(target.protocol)) return;
    // A whitelist entry exempts both pages on that host and links whose destination is that host.
    if (whitelist.some(rule => hostMatches(location.hostname, rule) || hostMatches(target.hostname, rule))) return;
    const result = sanitizeUrl(target.href);
    if (!result || !result.changed || result.href === target.href) return;
    // Updating href before default navigation preserves normal browser behavior and target/download attributes.
    anchor.href = result.href;
    anchor.dataset.phishguardSanitized = "true";
  }
  document.addEventListener("click", sanitizeAnchor, true);
  document.addEventListener("auxclick", sanitizeAnchor, true);
})();
