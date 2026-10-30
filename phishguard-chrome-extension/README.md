# PhishGuard Chrome Extension (Manifest V3)

A Chrome extension with a popup scanner, a user-triggered Gmail scan button, current-page URL checks, global opt-in hover reputation checks, and pre-click checks for file-like download links.

## Important status labels

- **Live integration result** means the backend reported provider checks (for example, VirusTotal or Google Safe Browsing). Provider coverage depends on backend configuration and API quotas.
- **No threat detected** is not the same as safe. New, targeted, or unreported threats may not be detected.
- The extension itself does not embed API keys or call reputation providers directly. Keys stay in the PhishGuard backend.
- Website and hover checks use `POST /api/check-url`; email checks use `POST /api/analyze`.

## Load in Chrome

1. Unzip this folder.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select this `phishguard-chrome-extension` folder.
5. Pin PhishGuard from the Extensions menu.

## Configure the backend

1. Start or deploy the existing PhishGuard backend.
2. Click the PhishGuard extension icon.
3. Enter the backend base URL, for example `http://localhost:3000` for local testing or `https://your-deployed-host.example`.
4. Click **Save & authorize backend**. Chrome asks for permission to contact that backend origin. Grant only if you trust the URL. The extension now normalizes an accidental `/api` suffix and reports actionable backend errors on hover instead of hiding the reason.
5. The extension calls `GET <backend URL>/api/health` to verify connectivity, then uses the appropriate API route for each scan.

The backend must have valid server-side environment variables for VirusTotal and/or Google Safe Browsing if live reputation checks are wanted. Restart the backend after changing environment variables. The extension cannot fix invalid provider keys.

### Localhost notes

- `http://localhost:3000` is suitable when Chrome and the backend are running on the same computer.
- Do not use localhost as the backend URL for a deployed extension used on another device.
- For public deployment, use HTTPS and protect the backend with rate limiting and authentication before sharing it widely.

## Features

### Popup
- Configure backend URL and request permission for its origin.
- Scan the current page URL without opening it.
- Enable or disable hover and pre-download checks on all HTTP/HTTPS websites after granting optional site access.

### Gmail
- Adds a floating **Scan with PhishGuard** button on Gmail.
- Only reads the currently visible message after the user clicks the button.
- Prefers the last visible message body and scopes sender/attachment extraction to that message when possible.
- Extracts actual HTTP/HTTPS link destinations from the message HTML, even when the displayed link text says “Click here”. It does not open those links.
- Filters Gmail UI labels and detects likely attachment download links in the currently open email.
- When you click the Gmail scan button, it attempts to download up to 3 attachments (maximum 10 MB each) and sends them to your configured backend for SHA-256 / VirusTotal reputation checks. It does not execute attachments. Gmail UI changes may prevent attachment extraction.
- The report displays the risk score, findings, URL reputation, and recommended actions without provider configuration banners or long attachment disclaimers.
- Gmail DOM structure can change; if a field is missing, paste the email into the popup instead.
- The visible Gmail DOM does not expose full raw headers reliably. Header authentication checks require headers to be provided separately.

### Website link and download checks
- Global protection is opt-in. Chrome asks for HTTP/HTTPS site access only when you enable it.
- Hover or keyboard-focus a link to check its URL; file-like download links get a download-specific status.
- Clicking a file-like link pauses the click for a reputation check. High-risk links are blocked. Suspicious or inconclusive links require explicit confirmation; a provider-confirmed no-match result continues automatically.
- Green means a configured live provider returned no known match; amber means suspicious/inconclusive; red means high risk. These are signals, not guarantees.
- The extension checks the URL; it does not fetch every linked file before a click. Script-triggered downloads, browser-internal pages, and links without recognizable file/download signals may not be interceptable.

## Permissions

- `activeTab`: read the current tab URL after the user interacts with the extension.
- `scripting`: inject hover checking into the tab only after the user enables it.
- `storage`: store backend URL and hover preference.
- `https://mail.google.com/*`: Gmail content script for the explicit scan button.
- Optional `http://*/*` and `https://*/*` host permissions: used for the configured backend and for all-site protection only after you explicitly enable it. Chrome displays a permission prompt.

The extension does not request browsing history, downloads, or cookies. All-site access is not requested at install time; it is requested only if you turn on global protection.

## Safety and privacy

- Email scans are user-triggered. There is no automatic inbox crawling.
- The hover feature sends only the hovered URL to the configured backend.
- The website scan sends only the active page URL, not page contents.
- Gmail scan sends the visible sender, subject, body text, attachment filenames, and any detected attachment bytes to your configured backend after you click Scan. The backend checks hashes with VirusTotal; unknown files are uploaded to VirusTotal only if `PHISHGUARD_ALLOW_VT_FILE_UPLOAD=true` is set on the backend. VirusTotal submissions may be shared with the provider and partners, so do not enable uploads for confidential files unless authorized.
- Do not scan confidential email unless you trust and control the configured backend.
- Email text is rendered using `textContent`, not injected as HTML.
- The extension never executes attachments. When a supported Gmail attachment is detected, its bytes are sent to your configured backend; whether unknown files are uploaded to VirusTotal is controlled server-side by `PHISHGUARD_ALLOW_VT_FILE_UPLOAD`.
- Reputation checks and risk scores are not guarantees. A missing provider result may mean no report, an unavailable API, or a configuration issue.

## Backend API contract

Expected request:
```json
{
  "sender": "",
  "displayName": "",
  "subject": "Website URL check",
  "body": "https://example.com/",
  "attachments": "",
  "headers": ""
}
```

The backend needs `POST /api/analyze` and `POST /api/analyze-attachment`. The latter computes a SHA-256 hash and checks VirusTotal file reputation. Configure `VIRUSTOTAL_API_KEY` on the server. Unknown file upload is disabled by default; set `PHISHGUARD_ALLOW_VT_FILE_UPLOAD=true` only after reviewing privacy implications.

## Troubleshooting

- **Backend not configured:** save the backend URL in the popup.
- **Permission denied:** reopen popup and authorize the exact backend origin.
- **Failed to fetch:** verify the backend is running, URL is correct, HTTPS is used for deployed services, and the browser can reach it.
- **API integrations not live:** check backend logs and server `.env.local`; extension API keys are intentionally not supported.
- **Gmail button missing:** refresh Gmail and open an email. Gmail UI changes may require updating selectors.
- **Green highlight:** means no threat was detected by the configured checks, not a certified safe verdict.


## Global website and download protection (v1.2.0)

1. Load this extracted extension folder at `chrome://extensions` with Developer mode enabled.
2. Open the extension popup and save the PhishGuard backend URL. The extension calls `GET /api/health` to check that the backend is reachable.
3. Click **Enable download & hover protection on all websites** and approve Chrome's optional site-access prompt.
4. Hover links to see a compact risk status. Clicking a file-like download link pauses the click while the URL is checked. High-risk links are blocked; suspicious or inconclusive links require confirmation before proceeding.
5. Disable protection from the popup to unregister the global content script.

Protection applies to HTTP/HTTPS pages where Chrome permits extension injection. It checks URLs and does not download every linked file in advance. Some downloads triggered by page scripts, browser-internal pages, or links without recognizable download indicators may not be interceptable. A clean provider result is a reputation signal, not a guarantee.

## Backend API routes

- `GET /api/health` — backend and route availability.
- `POST /api/analyze` — email/text analysis.
- `POST /api/analyze-file` — multipart `.eml`/`.txt` analysis (`file` field).
- `POST /api/check-url` — URL reputation and heuristic checks (`{ "url": "https://example.com" }`).
- `POST /api/analyze-attachment` — multipart file reputation (`file` field).
- `GET /api/analyze-attachment/status?id=...` — polls asynchronous VirusTotal analysis.

API keys belong in the backend environment only. The extension does not store provider keys. Unknown files are not uploaded to VirusTotal unless `PHISHGUARD_ALLOW_VT_FILE_UPLOAD=true` is configured on the backend.


## CSV website blocklist dashboard (v1.3.0)

Open the extension popup and choose **Manage CSV blocklists**. Import one or more CSV files; each file becomes a separate source that can be enabled, disabled, or removed. CSV files are parsed locally and are not uploaded to the PhishGuard backend.

CSV format is intentionally restricted to one column of links: one full HTTP/HTTPS URL per row, with an optional `link` or `url` header. Choose **Blacklist** or **Whitelist** in the dashboard before import. The imported URLs are matched as normalized full URLs (not arbitrary string prefixes); hostname matching is case-insensitive while path and query casing is preserved. The dashboard does not accept action/reason/domain columns.

After importing a CSV, choose **Enable CSV blocking** in the dashboard and grant Chrome site access. Chrome's Declarative Net Request engine blocks matching top-level website navigations locally, before the page loads. The popup scanner and hover checker also consult enabled CSV rules. The dashboard includes a URL tester and a sample CSV.

CSV rules can block legitimate sites if the file is inaccurate. Disable a source or remove it to undo its rules. CSV website blocking is separate from backend reputation checks.


## CSV list format (updated)
Each CSV contains only one link per row. A single optional header (`link` or `url`) is accepted. When importing, choose the source type in the dashboard: **Blacklist** blocks matching listed links; **Whitelist** allows matching listed links and overrides CSV blacklist matches. A whitelist does not block every URL absent from the list. You can change each source type after import from its source card.

Example:
```csv
link
https://example-phishing.test/
https://example.org/fake-login
```


## Local URL tracker sanitization

Open **Manage CSV blocklists** and enable **URL sanitization**. Grant the requested HTTP/HTTPS site permission and refresh tabs that were already open. When a user clicks a normal HTTP/HTTPS link, PhishGuard removes a conservative set of known tracking parameters locally before navigation. It does not send URLs to the backend for cleaning.

In **Websites exempt from sanitization**, enter one hostname per line (for example `example.com`). A matching hostname is exempt when it is the current page or the link destination; subdomains are included. Keep exemptions narrow. The cleaner intentionally preserves likely authentication, signature, token, state, nonce, session, expiry, and cloud-storage signing parameters to avoid breaking legitimate links. Sanitization is click-time and cannot rewrite URLs used by page scripts or server-side redirects. It cannot remove tracking embedded in path segments, server-side redirects, or unknown custom parameters.
