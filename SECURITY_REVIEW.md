# VulnDash security review

**Review date:** 2026-10-24  
**Reviewed version:** 0.1.7 source; hardening changes prepared for 0.1.8  
**Review type:** Source-based application security review with focused local checks

## Executive summary

VulnDash is a small, read-only vulnerability catalogue viewer. Its browser calls a local HTTP service, which queries SQLite; a background process downloads EUVD data. I found no unauthenticated write or command-execution route in the reviewed code. The most significant risk is deployment-related: the Home Assistant app maps port 8099 directly to the host by default, and those requests do not pass through Home Assistant authentication. Anyone who can reach that port can read the dashboard and consume service resources.

The 0.1.8 changes bound request concurrency and user-controlled query work, protect CSV exports from spreadsheet formulas, add browser security headers, reduce sensitive query data in logs, and cap EUVD response downloads. The direct port remains enabled for compatibility with the documented installation experience and should be restricted to a trusted network.

## Scope and method

Reviewed the add-on source and its deployment/configuration files, including `vulndash/server.py`, `vulndash/index.html`, `vulndash/run.sh`, `vulndash/Dockerfile`, `vulndash/config.yaml`, `compose.yaml`, and user-facing deployment documentation. Traced the HTTP routes, ingress check, SQLite query construction, EUVD downloader, browser rendering, CSV export, container startup, and network exposure.

This was a static review plus local syntax and targeted database/input checks. No live Home Assistant instance, production database, external network target, authenticated host, or third-party infrastructure was probed. No dependency/SBOM or container-image scan was performed. The review cannot establish the security of Home Assistant, Docker, the host firewall, the EUVD service, or the runtime image.

## Architecture and attack surface

- **Home Assistant ingress:** serves the UI and read-only `/api/*` endpoints through the supervisor ingress proxy. In ingress mode the handler allows the supervisor proxy address `172.30.32.2` only.
- **Direct add-on port:** `8099/tcp` is published by default. This listener does not authenticate users through Home Assistant. The app exposes the same read-only UI and APIs on this listener.
- **Standalone Compose service:** publishes `127.0.0.1:8765` by default; configuration can bind it to other interfaces. It has no login.
- **HTTP endpoints:** `GET /`, static assets, `/api/status`, `/api/vulnerabilities`, and `/api/chart`. No mutating API route was found.
- **SQLite:** local database under the configured data directory. User filters are translated into SQL; values are parameterized.
- **Background sync:** invokes `curl` with an argument array (no shell), downloads EUVD JSON, and persists records and sync state.
- **Browser:** renders remote catalogue fields in the table, chart tooltip, and status. CSV export contains data originating from EUVD.
- **Logs:** service status and HTTP request logs are written to the configured container log stream.

## Findings

### VULN-01 — Direct host port bypasses Home Assistant authentication

**Severity: Moderate (deployment exposure; potentially High if internet-reachable)**  
**Status: Residual risk; documented and surfaced in deployment guidance**

The Home Assistant configuration publishes `8099/tcp` directly. Traffic to this port does not pass through Home Assistant's login/session checks. The dashboard and read-only API are therefore available to any device with network access to the add-on port. An exposed service also lets reachable clients consume the bounded query capacity and compete with legitimate users. The standalone Compose service is similarly unauthenticated if deliberately bound beyond loopback.

**Impact:** disclosure of the stored public vulnerability catalogue and sync status; service/resource consumption. The app contains no private vulnerability data by design, but local network policy may treat host access as sensitive.

**Recommendation:** keep 8099 on a trusted LAN and block it at the router/firewall from untrusted or internet networks. For ingress-only deployments, remove the `8099/tcp` host mapping (`ports: 8099/tcp: null`) in the local add-on configuration. For Compose, retain the default loopback bind unless remote access is necessary, and place any remote access behind an authenticated reverse proxy/VPN. A future opt-in port exposure setting would reduce accidental exposure but would change the current default behavior.

### VULN-02 — Concurrent requests and expensive filters could exhaust resources

**Severity: Low to Moderate**  
**Status: Fixed in 0.1.8**

The original threaded server created a thread for each connection, with no explicit worker cap or socket timeout. Search and chart operations can scan the local catalogue, and SQLite permits concurrent readers. A client able to reach the unauthenticated port could open many slow connections or issue repeated broad searches, consuming threads, CPU, and database handles.

**Fix:** cap active workers at eight, bound the accept queue, apply a 15-second socket timeout, and return HTTP 503 with `Retry-After` when saturated. Limit filter lengths, field count, page size/page number, CVSS range, chart bin count, and date syntax; use index-friendly date comparisons; skip row retrieval when pagination is beyond the result set. Search `%`, `_`, and backslash characters now behave literally rather than expanding SQL `LIKE` patterns.

**Residual:** eight concurrent queries can still use meaningful CPU on a small host; the direct-port exposure in VULN-01 remains relevant. SQLite's 30-second busy timeout and broad contains-searches can still add latency under load.

### VULN-03 — CSV formula injection through catalogue values

**Severity: Low**  
**Status: Fixed in 0.1.8**

An EUVD-sourced vendor, product, or description beginning with spreadsheet formula characters could be interpreted as a formula when a CSV export is opened in spreadsheet software.

**Fix:** CSV cells with leading whitespace followed by `=`, `+`, `-`, or `@` are prefixed with an apostrophe before normal CSV quoting. This reduces formula execution risk in common spreadsheet applications.

**Residual:** spreadsheet import behavior varies. Treat CSV files from any external data source as untrusted, especially if imported into software with nonstandard formula handling.

### VULN-04 — Search terms were included in access logs

**Severity: Low**  
**Status: Fixed in 0.1.8**

The standard HTTP access logger recorded the full request target, including the free-text search query. This could copy user-entered terms into Home Assistant/Supervisor logs and backups.

**Fix:** log client address, method, path, and status without the query string. Query strings remain visible to the user's browser and any network intermediary that terminates or records HTTP traffic.

### VULN-05 — Browser responses lacked baseline security headers

**Severity: Low**  
**Status: Fixed in 0.1.8**

Responses previously lacked an explicit content-security policy and several browser protections. Dynamic catalogue values are escaped in the UI and advisory links are restricted to HTTP(S), but missing headers reduced defense in depth if a rendering regression is introduced.

**Fix:** add `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`. The policy permits the page's existing inline scripts and styles, same-origin API connections/assets, and the existing data-image use; it disallows objects and restricts base/form targets.

**Residual:** the CSP includes `'unsafe-inline'` to preserve the current single-file dashboard. Moving scripts/styles to separate files would permit a stricter policy.

### VULN-06 — EUVD response size and upstream dependence

**Severity: Low (availability / operational)**  
**Status: Partially mitigated in 0.1.8**

The background downloader consumes an external EUVD endpoint. A compromised, misconfigured, or unexpectedly large upstream response could increase memory/disk use. Network outages or upstream 403 responses can interrupt refreshes, although existing SQLite data remains available.

**Fix:** curl requests now enforce a 20 MiB maximum file size in addition to the existing timeout and retry behavior.

**Residual:** upstream availability and data integrity are not controlled by this app. A downloaded response is trusted as catalogue data; UI output escaping and parameterized SQL limit the consequences of hostile fields. The synchronization path should be re-reviewed if new data formats or import features are added.

## Security controls observed

- Search SQL uses placeholders for values; table/column identifiers in the shared filter builder come only from fixed code constants.
- No API route for modifying records, changing configuration, or executing commands was found.
- EUVD fetch uses `subprocess.run()` with an argument list and does not invoke a shell.
- Browser-rendered catalogue strings are generally HTML-escaped; external links are constrained to HTTP(S), encoded for path segments, and opened with `noopener`/`noreferrer` protections.
- The server has no CORS allow-origin policy and does not set session cookies or accept authentication tokens.
- The database is stored in the app data volume; filesystem permissions and backup access are inherited from the host/add-on runtime.
- The add-on starts from the Home Assistant Python base image and runs as root, as is common for S6-based add-ons. A compromise of the app process therefore has the privileges available inside that container; host impact still depends on container/runtime isolation. The base image tag is versioned but not digest-pinned, so reproducible supply-chain verification is not provided by this repository.

## Hardening delivered in 0.1.8

- Bounded HTTP concurrency, request queue, and socket read time.
- Bounded and validated query fields, pagination, date values, CVSS values, field count, and chart inputs.
- Literal wildcard handling for user search terms and index-friendly date filtering.
- CSV formula neutralization.
- Browser security headers.
- Access-log query-string removal.
- Maximum EUVD response size.
- Updated Home Assistant app version and changelog.

## Residual risks and follow-up

- No authentication on direct port 8099 or on a Compose deployment deliberately bound to a non-loopback interface.
- The app process runs as container root; review this again if the deployment model changes or the base image permits a safe non-root runtime.
- The Home Assistant base image is referenced by a mutable tag rather than immutable digest. Pin and update it through a documented dependency update process if reproducible image provenance is required.
- No rate limiting per client, authentication, TLS termination, or request audit trail is implemented. Use network controls for exposure boundaries.
- The server trusts the configured EUVD endpoint and stores the upstream catalogue locally. Keep the endpoint fixed to the official service unless an administrator explicitly changes deployment configuration.

## Verification

- `python -m py_compile vulndash/server.py` — passed.
- `git diff --check` — passed.
- Focused local checks of SQL wildcard escaping, empty-database search/chart behavior, invalid CVSS, page and size bounds, filter length, and chart-bin limits — passed.

No exploit testing was run against a live Home Assistant deployment. The default direct host port should be considered reachable by the devices permitted by the host/network firewall.
