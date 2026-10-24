# Changelog

## 0.1.7

- Recover the failed page from existing error state when resuming an interrupted snapshot.


## 0.1.6

- Slow EUVD pagination and retry transient gateway 403 responses.
- Resume a failed five-year snapshot from its last completed page.


## 0.1.5

- Log full snapshot starts and per-month progress in Supervisor logs.
- Show the current snapshot window and page in the dashboard status.


## 0.1.4

- Use curl for EUVD downloads to match the working Home Assistant Terminal request.


## 0.1.3

- Parse EUVD publication timestamps so date filters and charts include recent records.
- Normalize existing SQLite date fields once during startup.


## 0.1.2

- Enable direct access on host port 8099 by default and retain the ingress panel.
- Reduce EUVD request bursts and report the failed request and response details.

## 0.1.1

- Fix container startup by letting S6 overlay run as PID 1.

## 0.1.0

- Initial Home Assistant app and Docker Compose deployment.
- Local SQLite snapshot with daily recent refresh and weekly five-year reconciliation.
- Dashboard queries the local database.
