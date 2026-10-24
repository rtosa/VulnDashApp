#!/usr/bin/env python3
"""Local EUVD snapshot service and web server for VulnDash."""
from __future__ import annotations

from bisect import bisect_right
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
from calendar import monthrange
from datetime import date, datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(APP_DIR.parent / "data")))
DB_PATH = DATA_DIR / "vulndash.sqlite3"
EUVD_API = os.environ.get(
    "EUVD_API_URL", "https://euvdservices.enisa.europa.eu/api/search"
)
HISTORY_YEARS = max(1, min(5, int(os.environ.get("HISTORY_YEARS", "5"))))
SYNC_INTERVAL_HOURS = max(1, min(720, int(os.environ.get("SYNC_INTERVAL_HOURS", "24"))))
RECENT_OVERLAP_DAYS = max(1, min(60, int(os.environ.get("SYNC_RECENT_DAYS", "14"))))
PORT = max(1, min(65535, int(os.environ.get("PORT", "8099"))))
HOST = os.environ.get("HOST", "0.0.0.0")
INGRESS_MODE = os.environ.get("HA_INGRESS", "0").lower() in ("1", "true", "yes")
PAGE_SIZE = 100
FULL_REFRESH_DAYS = 7
REQUEST_PAUSE_SECONDS = 0.5
LOGGER = logging.getLogger("vulndash")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def years_ago(day: date, years: int) -> date:
    try:
        return day.replace(year=day.year - years)
    except ValueError:
        return day.replace(year=day.year - years, day=28)


def normalize_date(value) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return iso_utc(datetime.fromtimestamp(value, tz=timezone.utc))
        except (OverflowError, OSError, ValueError):
            return None
    parsed = parse_iso(str(value))
    return iso_utc(parsed) if parsed else str(value).strip() or None


def flatten_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(part for part in (flatten_text(v) for v in value) if part)
    if isinstance(value, dict):
        for key in (
            "value", "name", "productName", "product_name", "product", "vendor",
            "title", "description", "text", "version",
        ):
            if value.get(key) is not None:
                result = flatten_text(value[key])
                if result:
                    return result
    return ""


def cvss_score(record: dict) -> float | None:
    value = record.get("baseScore", record.get("cvss", record.get("base_score")))
    if isinstance(value, dict):
        value = next(
            (value.get(key) for key in ("baseScore", "base_score", "score") if value.get(key) is not None),
            None,
        )
    try:
        score = float(value)
        return score if math.isfinite(score) and 0 <= score <= 10 else None
    except (TypeError, ValueError):
        return None


def cve_id(record: dict) -> str:
    aliases = record.get("aliases") or []
    if isinstance(aliases, str):
        aliases = re.split(r"[;,\s]+", aliases)
    if not isinstance(aliases, list):
        aliases = []
    candidates = [record.get("id"), record.get("enisa_id"), record.get("enisaId"), *aliases]
    return next((str(v) for v in candidates if v and CVE_RE.fullmatch(str(v))), "—")


def euvd_id(record: dict) -> str:
    for key in ("id", "enisaId", "enisa_id", "euvdId", "euvd_id"):
        value = record.get(key)
        if isinstance(value, str) and re.match(r"^EUVD-\d{4}-\d+", value, re.I):
            return value
    return ""


def record_key(record: dict) -> str:
    key = euvd_id(record) or record.get("id") or record.get("enisaId") or record.get("enisa_id")
    if key:
        return str(key)
    raw = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "EUVD-HASH-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_date(record: dict) -> str | None:
    for key in ("datePublished", "date_published", "published", "publishedDate", "published_date", "date"):
        if record.get(key):
            return normalize_date(record[key])
    return None


def get_updated_date(record: dict) -> str | None:
    for key in ("dateUpdated", "date_updated", "updated", "lastModified", "last_modified", "modified"):
        if record.get(key):
            return normalize_date(record[key])
    return get_date(record)


def get_vendor(record: dict) -> str:
    names: list[str] = []

    def add(value):
        text = flatten_text(value).strip()
        if text and not re.match(r"^(unknown|n/?a|none|null|undefined|—|-+)$", text, re.I):
            if text.casefold() not in {n.casefold() for n in names}:
                names.append(text)

    for key in (
        "enisaIdVendor", "vulnerabilityVendor", "vulnerability_vendor", "vendors",
        "affectedVendors", "affected_vendors",
    ):
        value = record.get(key)
        for row in value if isinstance(value, list) else ([value] if value else []):
            if isinstance(row, str):
                add(row)
            elif isinstance(row, dict):
                vendor_value = row.get("vendor")
                if isinstance(vendor_value, dict):
                    vendor_value = vendor_value.get("name")
                manufacturer = row.get("manufacturer")
                if isinstance(manufacturer, dict):
                    manufacturer = manufacturer.get("name")
                add(
                    vendor_value or row.get("vendorName") or row.get("vendor_name")
                    or row.get("name") or manufacturer
                )
    for key in ("vendor", "vendorName", "vendor_name", "manufacturer"):
        value = record.get(key)
        if isinstance(value, str):
            add(value)
        elif isinstance(value, dict):
            add(value.get("name") or value.get("vendorName") or value.get("vendor_name"))
    return ", ".join(names) or "—"


def get_product(record: dict) -> str:
    names: list[str] = []

    def add(value):
        text = flatten_text(value).strip()
        if text and not re.match(r"^(unknown product|unknown|n/?a|none|null|undefined|—|-+)$", text, re.I):
            if text.casefold() not in {n.casefold() for n in names}:
                names.append(text)

    keys = (
        "enisaIdProduct", "vulnerabilityProduct", "affectedProducts", "affected_products",
        "products", "affectedSoftware", "affected_software", "vulnerableSoftware",
        "vulnerable_software",
    )
    rows = [row for key in keys for row in (record.get(key) if isinstance(record.get(key), list) else [])]
    for row in rows:
        if not isinstance(row, dict):
            continue
        product = row.get("product")
        if isinstance(product, dict):
            name = product.get("name") or product.get("productName")
        else:
            name = row.get("productName") or row.get("product_name") or row.get("name") or product
        add(name)
    for key in ("productName", "product_name", "product", "software"):
        value = record.get(key)
        if isinstance(value, str):
            add(value)
        elif isinstance(value, dict):
            product = value.get("product")
            add(value.get("name") or (product.get("name") if isinstance(product, dict) else product))
    return ", ".join(names) or "N/A"


def get_description(record: dict) -> str:
    for key in (
        "description", "descriptions", "summary", "details", "title",
        "vulnerabilityDescription", "vulnerability_description",
    ):
        text = flatten_text(record.get(key))
        if text and text != "[object Object]":
            return re.sub(r"\s+", " ", text).strip()
    for key, value in record.items():
        if re.search(r"description|summary|detail", key, re.I):
            text = flatten_text(value)
            if text:
                return re.sub(r"\s+", " ", text).strip()
    return "No description available."


def severity(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize(self) -> None:
        connection = self.connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    record_key TEXT PRIMARY KEY,
                    cve_id TEXT NOT NULL,
                    published_at TEXT,
                    updated_at TEXT,
                    cvss REAL,
                    severity TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    description TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    seen_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at);
                CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss);
                CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
                CREATE TABLE IF NOT EXISTS sync_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def set_state(self, **values) -> None:
        if not values:
            return
        connection = self.connect()
        try:
            connection.executemany(
                "INSERT INTO sync_state(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [(key, str(value)) for key, value in values.items()],
            )
            connection.commit()
        finally:
            connection.close()

    def get_state(self) -> dict[str, str]:
        connection = self.connect()
        try:
            return {row["key"]: row["value"] for row in connection.execute("SELECT key,value FROM sync_state")}
        finally:
            connection.close()

    def upsert(self, items: list[dict]) -> int:
        rows = []
        now = iso_utc()
        for item in items:
            if not isinstance(item, dict):
                continue
            score = cvss_score(item)
            rows.append(
                (
                    record_key(item),
                    cve_id(item),
                    get_date(item),
                    get_updated_date(item),
                    score,
                    severity(score),
                    get_vendor(item),
                    get_product(item),
                    get_description(item),
                    json.dumps(item, ensure_ascii=False, separators=(",", ":")),
                    now,
                )
            )
        if not rows:
            return 0
        connection = self.connect()
        try:
            connection.executemany(
                """
                INSERT INTO vulnerabilities
                    (record_key,cve_id,published_at,updated_at,cvss,severity,vendor,product,description,payload_json,seen_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_key) DO UPDATE SET
                    cve_id=excluded.cve_id,
                    published_at=excluded.published_at,
                    updated_at=excluded.updated_at,
                    cvss=excluded.cvss,
                    severity=excluded.severity,
                    vendor=excluded.vendor,
                    product=excluded.product,
                    description=excluded.description,
                    payload_json=excluded.payload_json,
                    seen_at=excluded.seen_at
                """,
                rows,
            )
            connection.commit()
        finally:
            connection.close()
        return len(rows)

    def prune(self, cutoff: date) -> int:
        connection = self.connect()
        try:
            cursor = connection.execute(
                "DELETE FROM vulnerabilities WHERE published_at IS NULL OR date(published_at) < date(?)",
                (cutoff.isoformat(),),
            )
            connection.commit()
            return cursor.rowcount
        finally:
            connection.close()

    def chart(self, query: dict[str, list[str]]) -> dict:
        raw_bins = query.get("bins", [""])[0]
        try:
            starts = [int(value) for value in raw_bins.split(",") if value]
            minimum = float(query.get("fromScore", ["0"])[0] or 0)
        except ValueError as error:
            raise ValueError("Invalid chart bins or score filter") from error
        if not starts or len(starts) > 600 or not math.isfinite(minimum):
            raise ValueError("Invalid chart request")
        bins = [
            {"time": start, "Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for start in starts
        ]
        clauses: list[str] = []
        values: list[object] = []
        date_from = query.get("fromDate", [""])[0]
        date_to = query.get("toDate", [""])[0]
        if date_from:
            clauses.append("date(published_at) >= date(?)")
            values.append(date_from)
        if date_to:
            clauses.append("date(published_at) <= date(?)")
            values.append(date_to)
        if minimum > 0:
            clauses.append("cvss >= ?")
            values.append(minimum)
        vendor = query.get("vendor", [""])[0].strip()
        product = query.get("product", [""])[0].strip()
        text = query.get("text", [""])[0].strip()
        if vendor:
            clauses.append("vendor LIKE ? COLLATE NOCASE")
            values.append("%" + vendor + "%")
        if product:
            clauses.append("product LIKE ? COLLATE NOCASE")
            values.append("%" + product + "%")
        if text:
            clauses.append(
                "(cve_id LIKE ? COLLATE NOCASE OR record_key LIKE ? COLLATE NOCASE "
                "OR vendor LIKE ? COLLATE NOCASE OR product LIKE ? COLLATE NOCASE "
                "OR description LIKE ? COLLATE NOCASE)"
            )
            pattern = "%" + text + "%"
            values.extend([pattern] * 5)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = "SELECT published_at,cvss FROM vulnerabilities" + where
        sql += " AND published_at IS NOT NULL" if where else " WHERE published_at IS NOT NULL"
        connection = self.connect()
        try:
            rows = connection.execute(sql, values)
            matched = 0
            for row in rows:
                published = parse_iso(row["published_at"])
                if not published:
                    continue
                timestamp = int(published.timestamp() * 1000)
                index = bisect_right(starts, timestamp) - 1
                if index < 0 or index >= len(bins):
                    continue
                matched += 1
                band = severity(row["cvss"])
                if band in bins[index]:
                    bins[index][band] += 1
            return {"bins": bins, "total": matched}
        finally:
            connection.close()
    def record_count(self) -> int:
        connection = self.connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0])
        finally:
            connection.close()

    def search(self, query: dict[str, list[str]]) -> dict:
        def first(name, default=""):
            return query.get(name, [default])[0]

        try:
            page = max(0, int(first("page", "0")))
            size = max(1, min(100, int(first("size", "50"))))
            minimum = float(first("fromScore", "0") or 0)
        except ValueError as error:
            raise ValueError("Invalid pagination or score filter") from error
        if not math.isfinite(minimum):
            raise ValueError("Invalid minimum score")

        clauses: list[str] = []
        values: list[object] = []
        date_from = first("fromDate")
        date_to = first("toDate")
        if date_from:
            clauses.append("date(published_at) >= date(?)")
            values.append(date_from)
        if date_to:
            clauses.append("date(published_at) <= date(?)")
            values.append(date_to)
        if minimum > 0:
            clauses.append("cvss >= ?")
            values.append(minimum)
        vendor = first("vendor").strip()
        product = first("product").strip()
        text = first("text").strip()
        if vendor:
            clauses.append("vendor LIKE ? COLLATE NOCASE")
            values.append("%" + vendor + "%")
        if product:
            clauses.append("product LIKE ? COLLATE NOCASE")
            values.append("%" + product + "%")
        if text:
            clauses.append(
                "(cve_id LIKE ? COLLATE NOCASE OR record_key LIKE ? COLLATE NOCASE "
                "OR vendor LIKE ? COLLATE NOCASE OR product LIKE ? COLLATE NOCASE "
                "OR description LIKE ? COLLATE NOCASE)"
            )
            pattern = "%" + text + "%"
            values.extend([pattern] * 5)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        connection = self.connect()
        try:
            total = int(
                connection.execute("SELECT COUNT(*) FROM vulnerabilities" + where, values).fetchone()[0]
            )
            rows = connection.execute(
                "SELECT payload_json FROM vulnerabilities"
                + where
                + " ORDER BY published_at DESC, record_key ASC LIMIT ? OFFSET ?",
                [*values, size, page * size],
            ).fetchall()
            items = []
            for row in rows:
                try:
                    items.append(json.loads(row["payload_json"]))
                except (TypeError, json.JSONDecodeError):
                    continue
            return {
                "items": items,
                "total": total,
                "metadata": {"count": total, "page": page, "size": size},
            }
        finally:
            connection.close()


def extract_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("items", "data", "results", "vulnerabilities"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
    return []


def month_windows(start: date, end: date):
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        month_start = date(year, month, 1)
        month_end = date(year, month, monthrange(year, month)[1])
        yield max(start, month_start), min(end, month_end)
        if month == 12:
            year, month = year + 1, 1
        else:
            month += 1


class SnapshotSync:
    def __init__(self, database: Database):
        self.database = database
        self.lock = threading.Lock()

    def fetch_page(self, start: date, end: date, page: int) -> list[dict]:
        parameters = urlencode(
            {
                "page": str(page),
                "size": str(PAGE_SIZE),
                "fromDate": start.isoformat(),
                "toDate": end.isoformat(),
            }
        )
        request = Request(
            EUVD_API + "?" + parameters,
            headers={
                "Accept": "application/json",
                "User-Agent": "VulnDashApp/0.1.2 (+https://github.com/rtosa/VulnDashApp)",
            },
        )
        for attempt in range(5):
            try:
                with urlopen(request, timeout=60) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                return extract_items(payload)
            except HTTPError as error:
                if error.code not in (429, 500, 502, 503, 504) or attempt == 4:
                    body = error.read(512).decode("utf-8", errors="replace").strip()
                    detail = f": {body}" if body else ""
                    raise RuntimeError(
                        f"EUVD returned HTTP {error.code} for {request.full_url}{detail}"
                    ) from error
                retry_after = error.headers.get("Retry-After")
                try:
                    delay = min(60, max(1, int(retry_after))) if retry_after else min(60, 2 ** attempt)
                except ValueError:
                    delay = min(60, 2 ** attempt)
                LOGGER.warning("EUVD HTTP %s; retrying in %s seconds", error.code, delay)
                time.sleep(delay)
            except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
                if attempt == 4:
                    raise RuntimeError(f"Could not fetch EUVD snapshot: {error}") from error
                delay = min(60, 2 ** attempt)
                LOGGER.warning("EUVD request failed; retrying in %s seconds", delay)
                time.sleep(delay)
        return []

    def fetch_window(self, start: date, end: date, phase: str, window_index: int, window_count: int) -> int:
        processed = 0
        page = 0
        while page < 500:
            items = self.fetch_page(start, end, page)
            if not items:
                break
            processed += self.database.upsert(items)
            self.database.set_state(
                sync_phase=phase,
                sync_progress=(
                    f"{start.isoformat()} to {end.isoformat()} · "
                    f"window {window_index}/{window_count} · page {page + 1} · "
                    f"{processed} records processed in this window"
                ),
            )
            if len(items) < PAGE_SIZE:
                break
            page += 1
            time.sleep(REQUEST_PAUSE_SECONDS)
        else:
            raise RuntimeError(f"EUVD pagination safety limit reached for {start} to {end}")
        return processed

    def full_sync(self) -> None:
        today = utc_now().date()
        cutoff = years_ago(today, HISTORY_YEARS)
        windows = list(month_windows(cutoff, today))
        self.database.set_state(
            sync_phase="full",
            sync_progress=f"Refreshing {HISTORY_YEARS} years · 0/{len(windows)} monthly windows",
            last_error="",
        )
        for index, (start, end) in enumerate(windows, start=1):
            self.database.set_state(
                sync_phase="full",
                sync_progress=f"Refreshing {start:%b %Y} · window {index}/{len(windows)}",
            )
            self.fetch_window(start, end, "full", index, len(windows))
        removed = self.database.prune(cutoff)
        timestamp = iso_utc()
        self.database.set_state(
            last_full_sync=timestamp,
            last_success=timestamp,
            sync_phase="idle",
            sync_progress="",
            last_error="",
        )
        LOGGER.info("Full snapshot complete: %s records; pruned %s outside the history window", self.database.record_count(), removed)

    def recent_sync(self) -> None:
        today = utc_now().date()
        start = today - timedelta(days=RECENT_OVERLAP_DAYS)
        self.database.set_state(
            sync_phase="daily",
            sync_progress=f"Refreshing recent records · {start.isoformat()} to {today.isoformat()}",
            last_error="",
        )
        self.fetch_window(start, today, "daily", 1, 1)
        cutoff = years_ago(today, HISTORY_YEARS)
        self.database.prune(cutoff)
        timestamp = iso_utc()
        self.database.set_state(
            last_success=timestamp,
            sync_phase="idle",
            sync_progress="",
            last_error="",
        )
        LOGGER.info("Daily refresh complete: %s records in local snapshot", self.database.record_count())

    def run(self) -> None:
        while True:
            try:
                with self.lock:
                    state = self.database.get_state()
                    last_full = parse_iso(state.get("last_full_sync"))
                    if last_full is None or utc_now() - last_full >= timedelta(days=FULL_REFRESH_DAYS):
                        self.full_sync()
                    else:
                        self.recent_sync()
            except Exception as error:
                LOGGER.exception("Snapshot refresh failed")
                self.database.set_state(
                    sync_phase="error",
                    sync_progress="",
                    last_error=str(error)[:500],
                )
                time.sleep(min(SYNC_INTERVAL_HOURS * 3600, 3600))
                continue
            time.sleep(SYNC_INTERVAL_HOURS * 3600)


DATABASE = Database(DB_PATH)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(APP_DIR), **kwargs)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def normalize_path(self, parsed_path: str) -> str:
        path = parsed_path
        prefix = self.headers.get("X-Ingress-Path", "").rstrip("/")
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            path = path[len(prefix):] or "/"
        return path or "/"

    def deny_untrusted_ingress_client(self) -> bool:
        if not INGRESS_MODE:
            return False
        try:
            address = ipaddress.ip_address(self.client_address[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            allowed = address == ipaddress.ip_address("172.30.32.2")
        except ValueError:
            allowed = False
        if not allowed:
            self.send_json(403, {"error": "Requests must come through Home Assistant ingress"})
        return not allowed

    def do_GET(self):
        if self.deny_untrusted_ingress_client():
            return
        parsed = urlsplit(self.path)
        path = self.normalize_path(parsed.path).rstrip("/") or "/"
        if path == "/api/vulnerabilities":
            try:
                self.send_json(200, DATABASE.search(parse_qs(parsed.query, keep_blank_values=True)))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception:
                LOGGER.exception("Local database search failed")
                self.send_json(500, {"error": "Local database query failed"})
            return
        if path == "/api/chart":
            try:
                self.send_json(200, DATABASE.chart(parse_qs(parsed.query, keep_blank_values=True)))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception:
                LOGGER.exception("Local chart query failed")
                self.send_json(500, {"error": "Local chart query failed"})
            return
        if path == "/api/status":
            state = DATABASE.get_state()
            self.send_json(
                200,
                {
                    "state": state.get("sync_phase", "starting"),
                    "progress": state.get("sync_progress", ""),
                    "last_success": state.get("last_success"),
                    "last_full_sync": state.get("last_full_sync"),
                    "last_error": state.get("last_error", ""),
                    "records": DATABASE.record_count(),
                    "history_years": HISTORY_YEARS,
                    "sync_interval_hours": SYNC_INTERVAL_HOURS,
                },
            )
            return
        if path.startswith("/api/"):
            self.send_json(404, {"error": "Unknown local API endpoint"})
            return
        self.path = urlunsplit(("", "", path, parsed.query, ""))
        super().do_GET()

    def log_message(self, fmt, *args):
        LOGGER.info("%s - %s", self.address_string(), fmt % args)


class DashboardServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    sync = SnapshotSync(DATABASE)
    threading.Thread(target=sync.run, name="euvd-snapshot-sync", daemon=True).start()
    server = DashboardServer((HOST, PORT), Handler)
    LOGGER.info("VulnDash local database UI listening on %s:%s", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Stopping VulnDash")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()




