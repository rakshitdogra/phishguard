export type Finding = { severity: "bad" | "warn" | "good" | "info"; title: string; detail: string; points: number; source: "heuristic" | "api" };
export type UrlResult = { url: string; domain: string; checks: { provider: string; status: string; detail: string }[] };
export type Analysis = {
  score: number; level: "Low" | "Medium" | "High" | "Critical"; findings: Finding[]; urls: UrlResult[];
  auth: Record<string, string | null>; actions: string[]; integrations: { virusTotal: string; safeBrowsing: string; mode: string };
  summary: string; analyzedAt: string;
};

const phraseRules: { re: RegExp; title: string; detail: string; points: number }[] = [
  { re: /\b(urgent|immediately|act now|within \d+ minutes?|expires today|right away)\b/i, title: "Urgency or time pressure", detail: "The message pressures the recipient to act quickly.", points: 12 },
  { re: /\b(suspended|locked|permanent restriction|account will be (?:closed|suspended)|lose access)\b/i, title: "Threat of account loss", detail: "Threats about account access can provoke rushed action.", points: 13 },
  { re: /\b(verify your identity|confirm your password|enter your password|login credentials|account details|one-time password|\botp\b)\b/i, title: "Credential or identity request", detail: "The message appears to request sensitive account information.", points: 17 },
  { re: /\b(enable (?:content|macros)|enable macros|disable antivirus|install this viewer)\b/i, title: "Risky attachment instruction", detail: "The message asks the recipient to enable potentially unsafe content or install software.", points: 20 },
  { re: /\b(prize|you have won|claim your reward|gift card)\b/i, title: "Prize or reward lure", detail: "Unexpected rewards can be used to lure recipients into unsafe actions.", points: 8 },
  { re: /\b(payment required|invoice overdue|late fee|wire transfer|gift cards)\b/i, title: "Payment pressure", detail: "Payment demands or consequences should be verified independently.", points: 8 },
  { re: /\b(unusual sign[- ]in|new sign[- ]in|unrecognized device|suspicious activity|account compromised)\b/i, title: "Security-alert lure", detail: "The message uses a security alert that could be legitimate or could be designed to trigger a rushed click.", points: 7 },
  { re: /\b(refund pending|failed delivery|delivery attempt|customs fee|package on hold)\b/i, title: "Delivery or refund lure", detail: "Delivery and refund notices are commonly imitated; verify them through the provider's official app or website.", points: 7 },
  { re: /\b(document shared|voicemail attached|view secure document|shared a file|review the document)\b/i, title: "Document-sharing lure", detail: "Unexpected document or voicemail links can lead to credential-harvesting pages.", points: 6 },
  { re: /\b(do not tell anyone|keep this confidential|keep this between us|bypass normal procedure)\b/i, title: "Secrecy or process-bypass request", detail: "Requests to hide the action or bypass normal controls are common in targeted social-engineering scams.", points: 12 },
  { re: /\b(refund|overpayment|accidental payment)\b/i, title: "Possible refund or overpayment scam", detail: "Unexpected refunds or overpayments should be confirmed independently before sharing details or sending money.", points: 5 }
];
const highRiskExt = /\.(exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|msi|hta|lnk|jar|reg|com|pif)$/i;
const riskyExt = /\.(html?|svg|zip|rar|7z|iso|img|docm|xlsm|pptm|one|chm|cab|vhd|vhdx)$/i;
const doubleExtensionRisk = /\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png)\.(exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|msi|hta|lnk|jar|com|pif)$/i;
const reservedDomains = /(^|\.)(example|test|invalid|localhost)$/i;

// Small, transparent brand set for typo-squatting checks. This is a heuristic,
// not an authoritative list of official domains; keep matches explainable.
const brandRules: { name: string; aliases: string[]; domains: string[] }[] = [
  { name: "PayPal", aliases: ["paypal"], domains: ["paypal.com"] },
  { name: "Google", aliases: ["google", "gmail"], domains: ["google.com", "gmail.com"] },
  { name: "Microsoft", aliases: ["microsoft", "outlook", "office365"], domains: ["microsoft.com", "outlook.com", "live.com", "office.com"] },
  { name: "Apple", aliases: ["apple", "icloud"], domains: ["apple.com", "icloud.com"] },
  { name: "Amazon", aliases: ["amazon"], domains: ["amazon.com", "amazon.in"] },
  { name: "Meta", aliases: ["facebook", "instagram", "meta"], domains: ["facebook.com", "instagram.com", "meta.com"] },
  { name: "Netflix", aliases: ["netflix"], domains: ["netflix.com"] },
  { name: "DHL", aliases: ["dhl"], domains: ["dhl.com"] },
  { name: "Adobe", aliases: ["adobe"], domains: ["adobe.com"] },
  { name: "LinkedIn", aliases: ["linkedin"], domains: ["linkedin.com"] },
  { name: "Bank of America", aliases: ["bankofamerica", "bofa"], domains: ["bankofamerica.com"] },
  { name: "Chase", aliases: ["chase"], domains: ["chase.com"] },
  { name: "FedEx", aliases: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", aliases: ["ups"], domains: ["ups.com"] },
  { name: "USPS", aliases: ["usps"], domains: ["usps.com"] },
  { name: "DocuSign", aliases: ["docusign"], domains: ["docusign.com"] },
  { name: "Dropbox", aliases: ["dropbox"], domains: ["dropbox.com"] },
  { name: "Zoom", aliases: ["zoom"], domains: ["zoom.us"] },
  { name: "Slack", aliases: ["slack"], domains: ["slack.com"] },
  { name: "Discord", aliases: ["discord"], domains: ["discord.com"] },
  { name: "Steam", aliases: ["steam", "steampowered"], domains: ["steampowered.com", "steamcommunity.com"] },
  { name: "Coinbase", aliases: ["coinbase"], domains: ["coinbase.com"] },
  { name: "Stripe", aliases: ["stripe"], domains: ["stripe.com"] },
  { name: "Spotify", aliases: ["spotify"], domains: ["spotify.com"] },
  { name: "Roblox", aliases: ["roblox"], domains: ["roblox.com"] },
  { name: "SBI", aliases: ["sbi", "onlinesbi"], domains: ["sbi.co.in", "onlinesbi.sbi"] },
  { name: "HDFC Bank", aliases: ["hdfc", "hdfcbank"], domains: ["hdfcbank.com"] },
  { name: "ICICI Bank", aliases: ["icici", "icicibank"], domains: ["icicibank.com"] },
  { name: "Paytm", aliases: ["paytm"], domains: ["paytm.com"] },
  { name: "Flipkart", aliases: ["flipkart"], domains: ["flipkart.com"] }
];
const consumerMailDomains = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"]);
function normalizeLookalikes(value: string): string {
  return value.toLowerCase().normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[０-９]/g, ch => String.fromCharCode(ch.charCodeAt(0) - 0xFEE0))
    .replace(/[1!|]/g, "l").replace(/0/g, "o").replace(/3/g, "e")
    .replace(/5/g, "s").replace(/\$/g, "s").replace(/@/g, "a");
}
function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0]; row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const old = row[j]; row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1)); prev = old;
    }
  }
  return row[b.length];
}
function isDomainOrSubdomain(domain: string, candidate: string): boolean {
  return domain === candidate || domain.endsWith(`.${candidate}`);
}
function isIpv4Host(host: string): boolean {
  const parts = host.split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
const sensitiveUrlParameter = /(?:^|[-_])(token|auth|authorization|signature|sig|key|secret|code|state|nonce|session|sid|jwt|password|pass|credential|expires|expiry)(?:$|[-_])/i;
function urlForReputationLookup(raw: string): { url: string; redacted: boolean } {
  const parsed = new URL(raw.startsWith("www.") ? `https://${raw}` : raw);
  let redacted = Boolean(parsed.username || parsed.password || parsed.hash);
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  for (const key of Array.from(parsed.searchParams.keys())) {
    if (sensitiveUrlParameter.test(key) || /^x-(?:amz|goog)-/i.test(key) || /^(?:awsaccesskeyid|googleaccessid)$/i.test(key)) {
      parsed.searchParams.delete(key);
      redacted = true;
    }
  }
  return { url: parsed.href, redacted };
}

export function extractUrls(text: string): string[] {
  const raw = text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
  const out: string[] = [];
  for (const value of raw) {
    const cleaned = value.replace(/[),.;!?\]}]+$/g, "");
    try {
      const parsed = new URL(cleaned.startsWith("www.") ? `https://${cleaned}` : cleaned);
      if ((parsed.protocol === "http:" || parsed.protocol === "https:") && !out.includes(cleaned)) out.push(cleaned);
    } catch { /* Ignore malformed URL-like text. */ }
  }
  return out.slice(0, 15);
}
function domainOfUrl(raw: string): string { try { return new URL(raw.startsWith("www.") ? `https://${raw}` : raw).hostname.toLowerCase(); } catch { return "unknown"; } }
function emailDomain(raw: string): string { const match = raw.match(/@([^\s<>;,]+)/); return match?.[1]?.replace(/[)>.,;]+$/g, "").toLowerCase() || ""; }
function parseAuth(headers: string): Record<string, string | null> {
  const results: Record<string, string | null> = { spf: null, dkim: null, dmarc: null };
  for (const key of Object.keys(results)) {
    const re = new RegExp(`\\b${key}\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b`, "i");
    const match = headers.match(re); results[key] = match?.[1]?.toLowerCase() || null;
  }
  return results;
}
function uniqueFindings(findings: Finding[]): Finding[] { const seen = new Set<string>(); return findings.filter(f => { const k = `${f.title}|${f.detail}`; if (seen.has(k)) return false; seen.add(k); return true; }); }

export async function analyzeEmail(input: { sender: string; displayName: string; subject: string; body: string; attachments: string; headers: string; attachmentHashes: string[] }): Promise<Analysis> {
  const { sender, displayName, subject, body, attachments, headers, attachmentHashes } = input;
  const findings: Finding[] = []; let score = 0;
  const add = (severity: Finding["severity"], title: string, detail: string, points = 0, source: Finding["source"] = "heuristic") => {
    // Informational/positive observations must never increase risk. Final scoring is
    // recalculated from deduplicated findings below to avoid duplicate-rule inflation.
    findings.push({ severity, title, detail, points: severity === "bad" || severity === "warn" ? points : 0, source });
  };
  const senderDomain = emailDomain(sender);
  const senderLocal = (sender.match(/^\s*<?([^@<>\s]+)@/)?.[1] || "").toLowerCase();
  const normalizedLocal = normalizeLookalikes(senderLocal).replace(/[^a-z0-9]/g, "");
  const normalizedDomain = normalizeLookalikes(senderDomain);
  const claimedText = `${displayName} ${subject}`.toLowerCase();
  const replyMatch = headers.match(/^\s*Reply-To:\s*.*?<?([^<>\s]+@[^<>\s]+)>?\s*$/im);
  const replyDomain = replyMatch ? emailDomain(replyMatch[1]) : "";
  const text = `${subject}\n${body}`;
  // Detect invisible direction/format controls that can disguise displayed text.
  if (/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(`${sender} ${displayName} ${subject} ${body}`)) {
    add("warn", "Invisible or bidirectional text characters", "The message contains invisible formatting characters that can make names, URLs, or file names appear different from their underlying text.", 10);
  }
  if (senderLocal && /[^\x00-\x7F]/.test(senderLocal)) {
    add("info", "Non-ASCII sender name", "The sender address contains non-ASCII characters. This can be legitimate, but inspect for lookalike characters if the sender claims to be a familiar brand.", 3);
  }
  if (!sender) add("warn", "Sender address missing", "Provide the sender address to assess its format and domain.", 2);
  else if (!sender.includes("@") || !senderDomain.includes(".")) add("warn", "Sender address format looks unusual", "The supplied sender does not resemble a standard email address.", 8);
  if (senderDomain && reservedDomains.test(senderDomain)) add("info", "Reserved/example sender domain", "This domain appears reserved for examples or testing; sample domains are not real-world reputation evidence.", 2);
  if (senderDomain && /(?:secure|verify|account|login|support|billing|bank|update|alert|office365|paypal|apple|amazon)/i.test(senderDomain) && !/(gmail\.com|outlook\.com|yahoo\.com|icloud\.com)$/i.test(senderDomain)) add("warn", "Trust-related wording in sender domain", "Words like login, verify or security in a domain do not prove that it belongs to the claimed organization.", 6);

  // Detect brand impersonation and typo-squatting in both the local part and domain.
  for (const brand of brandRules) {
    const aliases = brand.aliases;
    const claimedTokens = claimedText.replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean);
    const claimedBrand = aliases.some(alias => claimedTokens.includes(alias) || claimedTokens.some(token => alias.length >= 6 && token.startsWith(alias)));
    const officialDomain = brand.domains.some(domain => isDomainOrSubdomain(senderDomain, domain));
    const exactLocalBrand = aliases.includes(senderLocal.replace(/[^a-z0-9]/g, ""));
    const normalizedLocalBrand = aliases.some(alias => normalizedLocal === alias || (normalizedLocal.length >= 5 && editDistance(normalizedLocal, alias) <= 1));
    const normalizedDomainCore = normalizedDomain.split(".")[0] || "";
    const normalizedDomainBrand = aliases.some(alias => normalizedDomainCore === alias || (normalizedDomainCore.length >= 5 && editDistance(normalizedDomainCore, alias) <= 1));
    const rawDomainCore = senderDomain.split(".")[0] || "";
    const domainTokens = rawDomainCore.split(/[-_]/).filter(Boolean);
    const domainTypo = aliases.some(alias => domainTokens.some(token => token !== alias && token.length >= 4 && editDistance(normalizeLookalikes(token), alias) <= 1));

    if (domainTypo && !officialDomain) {
      add("bad", `Possible ${brand.name} lookalike domain`, `The sender domain “${senderDomain}” resembles ${brand.name}'s name. Check the exact domain before trusting it.`, 24);
      break;
    }
    if (normalizedDomainBrand && !officialDomain && normalizedDomainCore !== rawDomainCore) {
      add("bad", `Possible ${brand.name} character substitution`, `The sender domain contains characters that normalize to a ${brand.name}-like name; this can be used for impersonation.`, 24);
      break;
    }
    if (normalizedLocalBrand && !exactLocalBrand && (claimedBrand || normalizedLocal.length >= 5)) {
      add("warn", `Possible ${brand.name} lookalike sender address`, `The sender name “${senderLocal}” resembles ${brand.name} after common character substitutions or a small spelling change. Verify the sender independently.`, 25);
      break;
    }
    if (claimedBrand && !officialDomain) {
      if (consumerMailDomains.has(senderDomain)) {
        add("info", `${brand.name} name used with a consumer email provider`, `The sender uses ${senderDomain}, not a verified ${brand.name} organizational domain. This alone does not prove phishing, but it does not authenticate the claimed brand.`, 3);
      } else {
        add("warn", `Brand claim does not match sender domain`, `The message mentions ${brand.name}, but the sender domain ${senderDomain || "is unavailable"} is not in this detector's known domain list. Legitimate third-party services can also send brand emails.`, 9);
      }
      break;
    }
    if (claimedBrand && officialDomain && !exactLocalBrand && senderLocal && !/^(?:noreply|no-reply|notification|notifications|service|support|billing|security|account|team|mail|info)$/i.test(senderLocal)) {
      // No score: retain a useful context finding only if the sender local part itself is odd.
      if (normalizedLocalBrand && senderLocal !== normalizedLocal) add("info", `Brand-related sender address: ${brand.name}`, `The sender appears related to ${brand.name}; still review message content and links.`, 0);
    }
  }

  if (senderDomain.startsWith("xn--") || senderDomain.split(".").some(part => part.startsWith("xn--"))) add("warn", "Internationalized sender domain", `The sender domain “${senderDomain}” contains punycode. Inspect it carefully for characters that resemble other letters.`, 8);
  if (displayName && /\b(bank|paypal|microsoft|apple|amazon|it support|security team|help desk|customer support)\b/i.test(displayName)) {
    const displayTokens = displayName.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/);
    const mentioned = brandRules.find(brand => brand.aliases.some(alias => displayTokens.includes(alias)));
    if (mentioned && !mentioned.domains.some(domain => isDomainOrSubdomain(senderDomain, domain))) add("warn", "Brand display name with unrelated sender domain", `The display name claims to represent ${mentioned.name}, but the sender domain is ${senderDomain || "missing"}. Display names can be forged.`, 12);
  }
  for (const rule of phraseRules) if (rule.re.test(text)) add("warn", rule.title, rule.detail, rule.points);

  if (/\b(?:password|passcode|one[- ]time code|\botp\b|recovery code|seed phrase|private key)\b/i.test(text) && /\b(?:reply|send|share|provide|confirm|enter|submit|verify)\b/i.test(text)) {
    add("warn", "Request to disclose an authentication secret", "The message combines a sensitive credential or recovery secret with an instruction to disclose it. Legitimate support teams should not ask for passwords or recovery codes by email.", 22);
  }
  if (/\b(?:scan the qr|scan this qr|qr code to sign in|approve the sign[- ]in|approve login|number matching)\b/i.test(text)) {
    add("warn", "Possible QR-code or login-approval lure", "The message asks you to scan a QR code or approve a sign-in. Verify the request through the service's official app or website.", 12);
  }
  if (/\b(?:crypto|cryptocurrency|bitcoin|wallet)\b/i.test(text) && /\b(?:seed phrase|recovery phrase|private key|connect your wallet)\b/i.test(text)) {
    add("bad", "Cryptocurrency wallet secret or access request", "The message refers to wallet secrets or wallet access, which can lead to irreversible loss of funds.", 25);
  }
  if (/\b(?:gift card|wire transfer|bank transfer|crypto|bitcoin)\b/i.test(text) && /\b(?:ceo|director|boss|urgent|confidential|keep this secret|don't tell)\b/i.test(text)) {
    add("warn", "Possible business email compromise or payment scam", "The message combines a payment method with urgency, authority, or secrecy. Confirm using a known, separate contact channel.", 16);
  }
  if (!subject) add("info", "Subject not provided", "Analysis is based on the fields supplied.", 0);

  const urls = extractUrls(body);
  if (urls.length) add("info", `${urls.length} URL${urls.length === 1 ? "" : "s"} extracted`, "URLs are checked without opening them. External reputation results depend on configured API keys.", Math.min(8, urls.length * 2));
  else add("good", "No visible URLs extracted", "No recognizable HTTP/HTTPS or www links were found in the supplied body.", 0);
  for (const raw of urls) {
    const domain = domainOfUrl(raw);
    if (/^http:\/\//i.test(raw)) add("warn", "Unencrypted HTTP link", `${domain} uses HTTP. HTTPS itself would not prove a site is trustworthy.`, 6);
    let parsedUrl: URL | null = null;
    try { parsedUrl = new URL(raw.startsWith("www.") ? `https://${raw}` : raw); } catch { /* already filtered by extractUrls */ }
    if (parsedUrl && isIpv4Host(parsedUrl.hostname)) add("warn", "Link uses a raw IP address", `The link points directly to IP address ${parsedUrl.hostname} instead of a recognizable domain. This is unusual for many legitimate account notices.`, 10);
    if (parsedUrl && parsedUrl.port && !["80", "443"].includes(parsedUrl.port)) add("warn", "Link uses a non-standard port", `The link host ${domain} uses port ${parsedUrl.port}. Verify the destination before opening it.`, 6);
    if (parsedUrl && parsedUrl.username) add("bad", "Link contains misleading user-info syntax", `The URL contains text before the @ sign that may make a different host appear trustworthy. The actual host is ${domain}.`, 12);
    if (domain.split(".").length >= 5) add("info", "Deeply nested link domain", `The link host ${domain} has several subdomain levels. This can be legitimate, but carefully identify the registrable domain before trusting it.`, 3);
    if (/(?:@|%40)/i.test(raw.split("://")[1] || "")) add("warn", "URL may obscure its destination", `Review the URL syntax carefully; user-info syntax can mislead readers.`, 8);
    if (/xn--/i.test(domain)) add("warn", "Punycode domain", `${domain} uses internationalized-domain encoding; check for lookalike characters.`, 6);
    if (/(bit\.ly|tinyurl\.com|t\.co|shorturl\.at|is\.gd)$/i.test(domain)) add("warn", "Shortened URL", `${domain} hides the final destination.`, 5);
    if (/\b(login|verify|secure|account|update|wallet|password)\b/i.test(domain)) add("warn", "Sensitive-action wording in URL", `${domain} contains words often used in login or verification lures. This is a heuristic only.`, 4);
    const domainCore = domain.split(".")[0] || "";
    for (const brand of brandRules) {
      const claimsBrand = brand.aliases.some(alias => domain.toLowerCase().includes(alias));
      const official = brand.domains.some(candidate => isDomainOrSubdomain(domain, candidate));
      const normalizedCore = normalizeLookalikes(domainCore);
      const urlDomainTokens = domainCore.split(/[-_]/).filter(Boolean).map(normalizeLookalikes);
      const lookalike = brand.aliases.some(alias => urlDomainTokens.some(token => token !== alias && token.length >= 4 && editDistance(token, alias) <= 1));
      if (!official && lookalike) {
        add("bad", `Possible ${brand.name} lookalike link`, `The link host “${domain}” resembles ${brand.name}. Do not sign in through this link; visit the official site directly.`, 20);
        break;
      }
      if (!official && claimsBrand && /(?:login|verify|secure|account|support|billing|update)/i.test(domain)) {
        add("warn", `Unverified ${brand.name}-related link`, `The link mentions ${brand.name} but is not in this detector's known official-domain list. Verify it independently.`, 10);
        break;
      }
    }
    if (senderDomain && domain !== senderDomain && !domain.endsWith(`.${senderDomain}`) && !senderDomain.endsWith(`.${domain}`)) add("info", "Link and sender domains differ", `The link host ${domain} differs from sender domain ${senderDomain}; legitimate services can also use different domains.`, 3);
  }
  const fileNames = attachments.split(/[,\n;]+/).map(v => v.trim()).filter(Boolean).slice(0, 30);
  for (const filename of fileNames) {
    if (doubleExtensionRisk.test(filename)) add("bad", "Misleading double-extension attachment", `${filename} ends with an executable or script extension despite using a document or image-looking name. Do not open it.`, 24);
    else if (highRiskExt.test(filename)) add("warn", "High-risk attachment extension", `${filename} has an executable or script-related extension. The file itself was not uploaded or inspected.`, 16);
    else if (riskyExt.test(filename)) add("warn", "Potentially risky attachment type", `${filename} may contain active content or an archive. Verify it before opening.`, 8);
    else add("info", "Attachment filename supplied", `${filename} was listed, but no file contents were inspected.`, 1);
  }
  if (!fileNames.length) add("good", "No attachment filenames supplied", "No attachment filenames were entered; this does not prove the original email had no attachments.", 0);

  const auth = parseAuth(headers);
  if (headers.trim()) {
    // From/Reply-To alignment is only a signal; mailing platforms may legitimately differ.
    for (const [key, value] of Object.entries(auth)) {
      if (value === "fail" || value === "softfail" || value === "permerror") add("warn", `${key.toUpperCase()} result: ${value}`, `The pasted header text reports ${key.toUpperCase()} ${value}. This app parses text only and does not independently verify the result.`, value === "fail" ? 12 : 7);
      else if (value === "none" || value === "neutral" || value === "temperror") add("info", `${key.toUpperCase()} result: ${value}`, `The pasted header text reports ${key.toUpperCase()} ${value}; this is inconclusive and needs context.`, 2);
      else if (value === "pass") add("good", `${key.toUpperCase()} result: pass`, `The pasted header text reports ${key.toUpperCase()} pass; this result is not independently verified here.`, 0);
      else add("info", `${key.toUpperCase()} result not found`, `No readable ${key.toUpperCase()} result was found in the supplied headers.`, 1);
    }
    if (replyDomain && senderDomain && replyDomain !== senderDomain && !replyDomain.endsWith(`.${senderDomain}`)) add("warn", "Reply-To domain differs", `Replies appear directed to ${replyDomain}, while the sender domain is ${senderDomain}. Verify this independently.`, 10);
    const fromHeader = headers.match(/^\s*From:\s*(.+)$/im)?.[1] || "";
    const fromHeaderDomain = emailDomain(fromHeader);
    if (fromHeaderDomain && senderDomain && fromHeaderDomain !== senderDomain && !fromHeaderDomain.endsWith(`.${senderDomain}`) && !senderDomain.endsWith(`.${fromHeaderDomain}`)) add("warn", "Supplied sender differs from From header", `The sender field domain ${senderDomain} differs from the parsed From header domain ${fromHeaderDomain}. This can indicate a parsing mismatch or spoofing; verify the original headers.`, 8);
    const returnMatch = headers.match(/^\s*Return-Path:\s*.*?<?([^<>\s]+@[^<>\s]+)>?/im);
    const returnDomain = returnMatch ? emailDomain(returnMatch[1]) : "";
    if (returnDomain && senderDomain && returnDomain !== senderDomain && !returnDomain.endsWith(`.${senderDomain}`)) add("info", "Return-Path differs from sender domain", `Return-Path domain ${returnDomain} differs from sender domain ${senderDomain}; mailing services can make this legitimate.`, 3);
  } else {
    add("info", "Email headers not provided", "SPF, DKIM and DMARC cannot be assessed from the body alone.", 0);
  }

  const uniqueUrls = urls.map(url => ({ url, domain: domainOfUrl(url), checks: [] as UrlResult["checks"] }));
  const integrations = { virusTotal: process.env.VIRUSTOTAL_API_KEY ? "Configured" : "Not configured", safeBrowsing: process.env.GOOGLE_SAFE_BROWSING_API_KEY ? "Configured" : "Not configured", mode: process.env.PHISHGUARD_OFFLINE_MODE === "true" ? "Offline" : "API checks enabled when configured" };
  const offline = process.env.PHISHGUARD_OFFLINE_MODE === "true";
  if (!offline) {
    await Promise.all(uniqueUrls.map(async item => {
      let reputationUrl = item.url;
      try {
        const prepared = urlForReputationLookup(item.url);
        reputationUrl = prepared.url;
        if (prepared.redacted) item.checks.push({ provider: "Privacy protection", status: "Sensitive URL data omitted", detail: "Embedded credentials, fragments, and credential-like query parameters were removed before external reputation lookup." });
      } catch { /* URL extraction already validates these values. */ }
      if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
        try {
          const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(process.env.GOOGLE_SAFE_BROWSING_API_KEY)}`, {
            method: "POST", headers: { "Content-Type": "application/json" }, cache: "no-store", signal: AbortSignal.timeout(8000),
            body: JSON.stringify({ client: { clientId: "phishguard-demo", clientVersion: "1.0.0" }, threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url: reputationUrl }] } })
          });
          if (response.ok) {
            const data = await response.json();
            if (Array.isArray(data.matches) && data.matches.length) {
              item.checks.push({ provider: "Google Safe Browsing", status: "Threat match", detail: "Google Safe Browsing reported a threat match for this URL." });
              add("bad", "Google Safe Browsing threat match", `Google Safe Browsing reported a threat match for ${item.domain}.`, 35, "api");
            } else item.checks.push({ provider: "Google Safe Browsing", status: "No match returned", detail: "No match was returned; this is not a guarantee of safety." });
          } else item.checks.push({ provider: "Google Safe Browsing", status: "Unavailable", detail: `Provider returned HTTP ${response.status}; result is inconclusive.` });
        } catch { item.checks.push({ provider: "Google Safe Browsing", status: "Unavailable", detail: "The provider could not be reached; result is inconclusive." }); }
      }
      if (process.env.VIRUSTOTAL_API_KEY) {
        try {
          const encoded = Buffer.from(reputationUrl).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
          const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(encoded)}`, { headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }, cache: "no-store", signal: AbortSignal.timeout(8000) });
          if (response.ok) {
            const data = await response.json(); const stats = data?.data?.attributes?.last_analysis_stats || {};
            const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0), total = Object.values(stats).reduce((sum: number, n: unknown) => sum + (typeof n === "number" ? n : 0), 0);
            item.checks.push({ provider: "VirusTotal", status: `${malicious} malicious · ${suspicious} suspicious`, detail: `Latest available analysis: ${malicious} malicious and ${suspicious} suspicious detections among ${total} reported results. A missing report is not proof of safety.` });
            if (malicious > 0) add("bad", "VirusTotal reports malicious detections", `${malicious} VirusTotal engines flagged ${item.domain} as malicious.`, Math.min(40, 15 + malicious * 3), "api");
            else if (suspicious > 0) add("warn", "VirusTotal reports suspicious detections", `${suspicious} VirusTotal engines flagged ${item.domain} as suspicious.`, 8, "api");
          } else if (response.status === 404) item.checks.push({ provider: "VirusTotal", status: "No report found", detail: "VirusTotal has no report for this URL identifier; no URL was submitted for scanning." });
          else item.checks.push({ provider: "VirusTotal", status: "Unavailable", detail: `Provider returned HTTP ${response.status}; result is inconclusive.` });
        } catch { item.checks.push({ provider: "VirusTotal", status: "Unavailable", detail: "The provider could not be reached; result is inconclusive." }); }
      }
      if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY && !process.env.VIRUSTOTAL_API_KEY) item.checks.push({ provider: "Live reputation", status: "Not configured", detail: "Configure VirusTotal and/or Google Safe Browsing API keys to enable live lookups." });
    }));
  } else uniqueUrls.forEach(item => item.checks.push({ provider: "Live reputation", status: "Disabled", detail: "PHISHGUARD_OFFLINE_MODE is enabled; no external API calls were made." }));

  // Hash-only reputation lookup: attachment bytes are never uploaded. VirusTotal may not have a report for every hash.
  if (attachmentHashes.length) {
    if (offline) {
      add("info", "Attachment hash lookup disabled", "Offline mode is enabled; supplied SHA-256 hashes were not sent to any provider.", 0);
    } else if (!process.env.VIRUSTOTAL_API_KEY) {
      add("info", "Attachment hash reputation not configured", "SHA-256 hashes were supplied, but VirusTotal is not configured. No file was uploaded.", 0);
    } else {
      await Promise.all(attachmentHashes.slice(0, 10).map(async hash => {
        try {
          const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, { headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY! }, cache: "no-store", signal: AbortSignal.timeout(8000) });
          if (response.ok) {
            const data = await response.json(); const stats = data?.data?.attributes?.last_analysis_stats || {};
            const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
            if (malicious > 0) add("bad", "VirusTotal reports malicious file hash", `SHA-256 ${hash} has ${malicious} malicious and ${suspicious} suspicious detections. The file itself was not uploaded.`, Math.min(35, 15 + malicious * 2), "api");
            else if (suspicious > 0) add("warn", "VirusTotal reports suspicious file hash", `SHA-256 ${hash} has ${suspicious} suspicious detections. The file itself was not uploaded.`, 8, "api");
            else add("good", "No malicious detections returned for file hash", `VirusTotal reported no malicious or suspicious detections for SHA-256 ${hash}; this is not a guarantee of safety.`, 0, "api");
          } else if (response.status === 404) add("info", "No VirusTotal report for attachment hash", `No report was found for SHA-256 ${hash}. No file was uploaded and absence of a report does not mean the file is safe.`, 0, "api");
          else add("info", "Attachment hash lookup unavailable", `VirusTotal returned HTTP ${response.status} for SHA-256 ${hash}; result is inconclusive.`, 0, "api");
        } catch { add("info", "Attachment hash lookup unavailable", `VirusTotal could not be reached for SHA-256 ${hash}; result is inconclusive.`, 0, "api"); }
      }));
    }
  }

  const finalFindings = uniqueFindings(findings);
  score = Math.max(0, Math.min(100, finalFindings.reduce((total, finding) => total + finding.points, 0)));
  const level: Analysis["level"] = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";
  const actions: string[] = [];
  if (score >= 25) actions.push("Do not click links, open unexpected attachments, reply, or provide passwords/OTPs until the sender is independently verified.");
  if (urls.length) actions.push("Open the organization's official website or app manually instead of following links in the message.");
  if (fileNames.length) actions.push("Do not open unexpected attachments. Use trusted endpoint protection or your security team to inspect files.");
  if (Object.values(auth).some(v => v === "fail" || v === "softfail") || (replyDomain && senderDomain && replyDomain !== senderDomain)) actions.push("Verify the sender through a known contact channel and report the message to your mail provider or security team.");
  if (score < 25) actions.push("This demo found few strong indicators, but that does not establish that the message is safe.");
  actions.push("If you already entered credentials, change them on the official site, revoke active sessions if available, and enable multifactor authentication.");
  return { score, level, findings: finalFindings, urls: uniqueUrls, auth, actions, integrations, summary: score >= 50 ? "Multiple concerning signals require caution." : score >= 25 ? "Some indicators need careful review." : "Few risk indicators were detected by the configured checks.", analyzedAt: new Date().toISOString() };
}
