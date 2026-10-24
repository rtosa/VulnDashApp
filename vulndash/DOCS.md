# VulnDash

VulnDash downloads EUVD records and stores a rolling five-year snapshot in `/data/vulndash.sqlite3`. The initial import covers the full history window. Daily refreshes re-fetch the most recent 14 days to catch additions and near-term corrections; a full five-year reconciliation runs weekly. Data stays available from SQLite if EUVD is temporarily unavailable.

## Home Assistant OS

Copy the `vulndash` folder to `/addons/local/vulndash` on the Home Assistant host. In Home Assistant, open **Settings → Apps**, use **Reload**, then install **VulnDash**. The web interface opens through Home Assistant ingress and is also published on host port 8099 by default. Open `http://<home-assistant-address>:8099` on your local network, or use the VulnDash sidebar panel. If port 8099 is already in use, choose another host port in the app configuration. Direct host-port access does not pass through Home Assistant authentication; keep it on a trusted network and do not expose it to the internet.

The app stores its database under `/data`, which Home Assistant persists and includes in app backups.

Options:
- `history_years`: retained publication history, 1–5 years (default 5).
- `sync_interval_hours`: daily refresh interval in hours, 1–168 (default 24).

Supported app architectures are `amd64` and `aarch64`.

## Home Assistant Container/Core

Home Assistant Container does not provide the Apps system. Run VulnDash as a companion container instead. The legacy Home Assistant Core and Supervised installation types are no longer supported by Home Assistant; this companion can run separately alongside a legacy Core install, but it is not an app integrated into that installation.

```sh
docker compose up -d --build
```

Copy `.env.example` to `.env` and adjust values if needed. Then the dashboard is available on the Docker host at `http://127.0.0.1:8765`. Set `VULNDASH_BIND_ADDRESS=0.0.0.0` in `.env` if you need to reach it from another device, and protect access with your network firewall. The standalone service has no separate login; do not expose it directly to the internet.

Set `HISTORY_YEARS` and `SYNC_INTERVAL_HOURS` in `.env` to change retention and refresh cadence. The SQLite file is persisted in `./data/`.

## Data source and operation

VulnDash contacts the official EUVD search API only from its background sync worker. The browser interface sends requests only to the local `/api` service, which reads from SQLite. Filters, pagination, sorting, severity chart data, and CSV export do not make requests to EUVD.

During the initial import, the dashboard is available while the database fills. The status line reports the number of records and last refresh. If an EUVD request fails, the app keeps serving its stored data and retries on the next refresh cycle.



