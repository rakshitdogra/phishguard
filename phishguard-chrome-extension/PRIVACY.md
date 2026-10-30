# Privacy summary

PhishGuard performs no automatic inbox scanning. Gmail content is read only after the user clicks the Scan with PhishGuard button. The extension submits the visible message fields to the backend URL chosen by the user.

The active website scanner sends only the active page URL. Hover checks send only the link URL currently hovered or keyboard-focused. The extension does not open links, download files, or upload attachment bytes.

The configured backend and any reputation providers it calls may process submitted URLs or email text according to their own logging and retention policies. Use a backend you trust; avoid submitting confidential messages unless you understand the backend's data handling.

The extension stores the configured backend URL and hover preference in Chrome extension storage. It does not store scanned email content or scan history.
