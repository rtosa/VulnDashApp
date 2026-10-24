# Changelog

## 0.1.2

- Enable direct access on host port 8099 by default and retain the ingress panel.
- Reduce EUVD request bursts and report the failed request and response details.

## 0.1.1

- Fix container startup by letting S6 overlay run as PID 1.

## 0.1.0

- Initial Home Assistant app and Docker Compose deployment.
- Local SQLite snapshot with daily recent refresh and weekly five-year reconciliation.
- Dashboard queries the local database.
