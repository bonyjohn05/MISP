#!/var/ossec/framework/python/bin/python3
import os, sqlite3, datetime, json, traceback
from collections import Counter
import requests
from requests.exceptions import ConnectionError, Timeout

MISP_URL        = os.getenv("MISP_URL", "https://misp.local").rstrip("/")
MISP_API_KEY    = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
MISP_TIMEOUT    = int(os.getenv("MISP_TIMEOUT_SEC", "60"))

MISP_USE_TIMESTAMP_FILTER = os.getenv("MISP_USE_TIMESTAMP_FILTER", "true").lower() == "true"
MISP_LAST_N_DAYS    = int(os.getenv("MISP_LAST_N_DAYS", "5000"))

MISP_TO_IDS_ONLY    = os.getenv("MISP_TO_IDS_ONLY", "false").lower() == "true"
MISP_PUBLISHED_ONLY = os.getenv("MISP_PUBLISHED_ONLY", "false").lower() == "true"
MISP_TAG_FILTER     = os.getenv("MISP_TAG_FILTER", "")
MISP_LIMIT          = int(os.getenv("MISP_LIMIT", "500"))    
MISP_MAX_PAGES      = int(os.getenv("MISP_MAX_PAGES", "5000"))

IPS_DB_PATH     = os.getenv("IPS_DB_PATH", "/var/ioc/ips.db")
HASHES_DB_PATH  = os.getenv("HASHES_DB_PATH", "/var/ioc/hashes.db")
DOMAINS_DB_PATH = os.getenv("DOMAINS_DB_PATH", "/var/ioc/domains.db")
URLS_DB_PATH    = os.getenv("URLS_DB_PATH", "/var/ioc/urls.db")

LOG_PATH        = os.getenv("MISP_SYNC_LOG", "/var/ossec/logs/misp-sync.log")
LOG_ENABLED     = os.getenv("MISP_SYNC_LOG_ENABLED", "true").lower() == "true"

SUPPRESS_TLS_WARN = os.getenv("MISP_SUPPRESS_TLS_WARN", "true").lower() == "true"
if SUPPRESS_TLS_WARN:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def log_line(obj: dict):
    if not LOG_ENABLED:
        return
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now_iso(), **obj}, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _sqlite_init(path: str, stmts: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
        for s in stmts:
            c.execute(s)
        c.commit()

def init_dbs():
    _sqlite_init(IPS_DB_PATH, [
        """CREATE TABLE IF NOT EXISTS ips (
            indicator TEXT PRIMARY KEY,
            source TEXT,
            updated_at TEXT,
            misp_event_id TEXT,
            misp_attribute_id TEXT,
            misp_type TEXT,
            misp_category TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_ips_updated_at ON ips(updated_at)"
    ])
    _sqlite_init(DOMAINS_DB_PATH, [
        """CREATE TABLE IF NOT EXISTS domains (
            indicator TEXT PRIMARY KEY,
            source TEXT,
            updated_at TEXT,
            misp_event_id TEXT,
            misp_attribute_id TEXT,
            misp_type TEXT,
            misp_category TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_domains_updated_at ON domains(updated_at)"
    ])
    _sqlite_init(URLS_DB_PATH, [
        """CREATE TABLE IF NOT EXISTS urls (
            indicator TEXT PRIMARY KEY,
            source TEXT,
            updated_at TEXT,
            misp_event_id TEXT,
            misp_attribute_id TEXT,
            misp_type TEXT,
            misp_category TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_urls_updated_at ON urls(updated_at)"
    ])
    _sqlite_init(HASHES_DB_PATH, [
        """CREATE TABLE IF NOT EXISTS hashes (
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            source TEXT,
            updated_at TEXT,
            misp_event_id TEXT,
            misp_attribute_id TEXT,
            misp_type TEXT,
            misp_category TEXT,
            PRIMARY KEY(indicator, type)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_hashes_updated_at ON hashes(updated_at)"
    ])

def tags_list():
    if not MISP_TAG_FILTER.strip():
        return []
    return [t.strip() for t in MISP_TAG_FILTER.split(",") if t.strip()]

def _ts_to_iso(ts):
    try:
        return datetime.datetime.utcfromtimestamp(int(ts)).replace(microsecond=0).isoformat() + "Z"
    except Exception:
        return now_iso()

def misp_rest_search(payload: dict) -> dict:
    if not MISP_API_KEY.strip():
        raise RuntimeError("MISP_API_KEY is empty")
    url = f"{MISP_URL}/attributes/restSearch"
    headers = {"Authorization": MISP_API_KEY, "Accept": "application/json", "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, verify=MISP_VERIFY_SSL, timeout=MISP_TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"MISP API error {r.status_code}: {r.text[:800]}")
    return r.json()

def upsert_many(db_path: str, sql: str, rows: list) -> int:
    if not rows:
        return 0
    with sqlite3.connect(db_path) as c:
        c.executemany(sql, rows)
        c.commit()
    return len(rows)

def run_sync_once():
    since_dt = datetime.datetime.utcnow() - datetime.timedelta(days=MISP_LAST_N_DAYS)
    since_epoch = int(since_dt.timestamp())

    base_payload = {
        "returnFormat": "json",
        "limit": MISP_LIMIT,
    }

    if MISP_USE_TIMESTAMP_FILTER:
        base_payload["timestamp"] = since_epoch

    t = tags_list()
    if t:
        base_payload["tags"] = t
    if MISP_TO_IDS_ONLY:
        base_payload["to_ids"] = 1
    if MISP_PUBLISHED_ONLY:
        base_payload["published"] = 1

    ip_rows, domain_rows, url_rows, hash_rows = [], [], [], []
    seen_types = Counter()
    pulled_total = 0
    skipped = 0

    for page in range(1, MISP_MAX_PAGES + 1):
        payload = dict(base_payload)
        payload["page"] = page

        data = misp_rest_search(payload)
        attrs = data.get("response", {}).get("Attribute", [])
        if not isinstance(attrs, list) or not attrs:
            break

        pulled_total += len(attrs)
        seen_types.update((a.get("type") or "null") for a in attrs)

        for a in attrs:
            try:
                atype = (a.get("type") or "").lower()
                val = (a.get("value") or "")
                event_id = str(a.get("event_id") or "")
                attr_id  = str(a.get("id") or "")
                mcat = a.get("category")
                updated_at = _ts_to_iso(a.get("timestamp"))
                src = "MISP"

                if atype in {"ip-src", "ip-dst", "ip", "ip-src|port", "ip-dst|port"}:
                    ip = val.split("|", 1)[0].strip()
                    if ip:
                        ip_rows.append((ip, src, updated_at, event_id, attr_id, atype, mcat))
                    else:
                        skipped += 1
                    continue

                if atype in {"domain", "hostname", "fqdn", "domain|ip"}:
                    d = val.split("|", 1)[0].strip().lower().rstrip(".")
                    if d:
                        domain_rows.append((d, src, updated_at, event_id, attr_id, atype, mcat))
                    else:
                        skipped += 1
                    continue

                if atype in {"url", "uri"}:
                    u = val.strip()
                    if u:
                        url_rows.append((u, src, updated_at, event_id, attr_id, atype, mcat))
                    else:
                        skipped += 1
                    continue

                if atype in {"md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"}:
                    if "|" in val:
                        h = val.split("|")[-1].strip().lower()
                        algo = atype.split("|")[-1].strip().lower()
                    else:
                        h = val.strip().lower()
                        algo = atype
                    if h:
                        hash_rows.append((h, algo, src, updated_at, event_id, attr_id, atype, mcat))
                    else:
                        skipped += 1
                    continue

                skipped += 1
            except Exception:
                skipped += 1

    stored_ip = upsert_many(
        IPS_DB_PATH,
        """INSERT INTO ips(indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(indicator) DO UPDATE SET
             source=excluded.source, updated_at=excluded.updated_at,
             misp_event_id=excluded.misp_event_id, misp_attribute_id=excluded.misp_attribute_id,
             misp_type=excluded.misp_type, misp_category=excluded.misp_category
        """,
        ip_rows,
    )
    stored_domain = upsert_many(
        DOMAINS_DB_PATH,
        """INSERT INTO domains(indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(indicator) DO UPDATE SET
             source=excluded.source, updated_at=excluded.updated_at,
             misp_event_id=excluded.misp_event_id, misp_attribute_id=excluded.misp_attribute_id,
             misp_type=excluded.misp_type, misp_category=excluded.misp_category
        """,
        domain_rows,
    )
    stored_url = upsert_many(
        URLS_DB_PATH,
        """INSERT INTO urls(indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(indicator) DO UPDATE SET
             source=excluded.source, updated_at=excluded.updated_at,
             misp_event_id=excluded.misp_event_id, misp_attribute_id=excluded.misp_attribute_id,
             misp_type=excluded.misp_type, misp_category=excluded.misp_category
        """,
        url_rows,
    )
    stored_hash = upsert_many(
        HASHES_DB_PATH,
        """INSERT INTO hashes(indicator, type, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(indicator, type) DO UPDATE SET
             source=excluded.source, updated_at=excluded.updated_at,
             misp_event_id=excluded.misp_event_id, misp_attribute_id=excluded.misp_attribute_id,
             misp_type=excluded.misp_type, misp_category=excluded.misp_category
        """,
        hash_rows,
    )

    breakdown = {"ip": stored_ip, "hash": stored_hash, "domain": stored_domain, "url": stored_url, "skipped": skipped}
    stored_total = stored_ip + stored_hash + stored_domain + stored_url

    log_line({
        "event": "misp_sync_done",
        "timestamp_filter": MISP_USE_TIMESTAMP_FILTER,
        "since_epoch": since_epoch,
        "since_utc": since_dt.replace(microsecond=0).isoformat() + "Z",
        "pulled": pulled_total,
        "seen_types": dict(seen_types),
        "stored": stored_total,
        "breakdown": breakdown,
        "pages_used": sum(1 for _ in range(1, MISP_MAX_PAGES + 1))
    })

    print(f"pulled={pulled_total} seen_types={dict(seen_types)} stored={stored_total} breakdown={breakdown}")
    return 0

def main():
    init_dbs()
    try:
        run_sync_once()
    except (ConnectionError, Timeout) as e:
        log_line({"event": "misp_sync_error", "error": str(e)})
        print("misp connection error")
    except Exception:
        log_line({"event": "misp_sync_error", "error": traceback.format_exc()})
        print("misp sync failed")

if __name__ == "__main__":
    main()
