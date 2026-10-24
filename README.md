# VulnDashApp

A Home Assistant app and standalone Docker deployment for the VulnDash vulnerability dashboard. It periodically snapshots the official ENISA EUVD catalogue into a local SQLite database and serves the existing dashboard UI from that database.

## Install as a Home Assistant app

Add `https://github.com/rtosa/VulnDashApp` in Home Assistant under **Settings → Apps → Install app → ⋮ → Repositories**. The app will appear as **VulnDash**.

## Choose a deployment

- **Home Assistant OS:** install the app through the local apps folder; it opens inside Home Assistant using ingress.
- **Home Assistant Container:** run the companion container with Docker Compose. Home Assistant Container does not include the Apps system, so this dashboard runs beside it.

See [vulndash/DOCS.md](vulndash/DOCS.md) for installation, options, storage, and network details.

The default configuration keeps five years of publication history and refreshes daily. It re-fetches the latest 14 days on daily cycles and rechecks the full five-year window weekly. SQLite data is persisted under `data/` (or `/data` in the Home Assistant app).
