# PhishGuard code review and repair report

## Scope reviewed

Reviewed the supplied Chrome Extension (Manifest V3) and Next.js backend/UI bundle, including the extension service worker, popup, dashboard, Gmail integration, URL sanitizer, download guard, API routes, analyzer, styles, manifest/configuration, and project documentation.

## Repairs applied

### Detection and reputation logic
- Risk scores are now calculated from deduplicated findings. Informational and positive findings no longer add risk points.
- Removed an overly broad Microsoft `office` brand alias that could incorrectly flag ordinary office-related messages.
- URL reputation requests now omit embedded URL credentials, fragments, and credential-like query parameters (tokens, signatures, session values, cloud signing fields) before sending the URL to external providers.
- Corrected VirusTotal URL identifiers to use URL-safe Base64 encoding.
- Added bounded timeouts to external VirusTotal and Google Safe Browsing requests.
- URL-only scans now use a scanner identity rather than generating a misleading missing-sender warning.

### Extension behavior
- CSV URL matching is now exact rather than prefix-based, preventing a listed `/login` URL from accidentally matching `/login-other`.
- URL path/query casing is preserved during exact matching; hostnames remain normalized by the URL parser.
- Chrome DNR URL filters now use a URL boundary delimiter.
- CSV blocking toggle failures roll back the enabled flag instead of leaving the UI in a false-enabled state.
- CSV imports enforce the combined 4,500-rule ceiling to match the service worker's dynamic-rule limit.
- Synthetic page-script clicks no longer trigger download-confirmation dialogs; real user clicks remain guarded.
- The in-memory hover/download result cache is capped to prevent unbounded growth.
- Remotely hosted backend URLs must use HTTPS; HTTP remains available for localhost development.

### UI, configuration, and documentation
- Refined the web app, extension dashboard, and popup visual styling with clearer hierarchy, responsive behavior, focus states, and reduced-motion support.
- Removed invalid nested `<main>` landmarks in the web app.
- Added baseline response security headers in Next.js configuration.
- Corrected documentation that previously described CSV multi-column/action imports even though the implemented importer accepts one link column and a separately selected list mode.
- Updated security/privacy notes to describe the optional VirusTotal file-upload path accurately.

## Validation performed

- `node --check` passed for every extension JavaScript file.
- TypeScript syntax transpilation passed for every backend `.ts` and UI `.tsx` file.
- Strict TypeScript checking passed for the backend analyzer and API routes using temporary ambient declarations for unavailable dependencies.
- JSON parsing passed for all JSON configuration files.
- Runtime analyzer smoke tests passed for benign and high-risk samples.
- Provider-request smoke test confirmed sensitive URL query data and fragments are removed before the VirusTotal lookup URL is constructed.

## Validation limitation / remaining production work

A full Next.js production build and dependency-backed whole-project typecheck could not be completed in this environment because `npm install` did not finish before the available command timeout. Run `npm install`, `npm run typecheck`, and `npm run build` in the target environment before deployment.

The backend still has no user authentication or distributed rate limiting. Do not expose it publicly without an authenticated gateway/WAF and per-IP/account limits. Heuristic and reputation results are indicators, not proof that an email or URL is safe. Gmail selectors and browser download interception can also be affected by future Gmail/Chrome behavior changes.
