#!/var/ossec/framework/python/bin/python3
import sys
import os
import json
import re
import sqlite3
import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM

WAZUH_BASE = "/var/ossec"
QUEUE_SOCKET = f"{WAZUH_BASE}/queue/sockets/queue"
PROGRAM_NAME = "ioc_sqlite"  

IPS_DB_PATH     = os.getenv("IPS_DB_PATH", "/var/ioc/ips.db")
HASHES_DB_PATH  = os.getenv("HASHES_DB_PATH", "/var/ioc/hashes.db")
DOMAINS_DB_PATH = os.getenv("DOMAINS_DB_PATH", "/var/ioc/domains.db")
URLS_DB_PATH    = os.getenv("URLS_DB_PATH", "/var/ioc/urls.db")

MAX_LOOKUPS_PER_TYPE = int(os.getenv("IOC_MAX_LOOKUPS_PER_TYPE", "200"))
SKIP_NO_MATCH = os.getenv("IOC_SKIP_NO_MATCH", "true").lower() == "true"

RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN = re.compile(r"\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def deep_get(obj, dotted: str):
    cur = obj
    for p in dotted.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur

def deep_collect_strings(obj):
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(deep_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(deep_collect_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out

def normalize_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")

def db_exists(path: str) -> bool:
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except Exception:
        return False

def to_flag_map(values):
    """No arrays: {"value": true, ...}"""
    m = {}
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if v:
            m[v] = True
    return m

def tags_map():
    return {
        "threatintel": True,
        "ioc": True,
        "sqlite-cache": True,
        "misp": True
    }

def send_event(payload: dict, agent: dict):
    agent_id = (agent or {}).get("id", "000")
    if agent_id == "000":
        wire = f"1:{PROGRAM_NAME}:{json.dumps(payload, ensure_ascii=False)}"
    else:
        wire = "1:[{id}] ({name}) {ip}->{prog}:{payload}".format(
            id=agent.get("id", "000"),
            name=agent.get("name", "unknown"),
            ip=agent.get("ip", "any"),
            prog=PROGRAM_NAME,
            payload=json.dumps(payload, ensure_ascii=False),
        )

    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(QUEUE_SOCKET)
    sock.send(wire.encode())
    sock.close()

def is_own_event(alert: dict) -> bool:
    """
    Stop recursion: if this alert/event is produced by this integration, exit.
    Covers common Wazuh shapes.
    """
    if alert.get("integration") == PROGRAM_NAME:
        return True

    pre = alert.get("predecoder") or {}
    if isinstance(pre, dict) and pre.get("program_name") == PROGRAM_NAME:
        return True

    if alert.get("program_name") == PROGRAM_NAME:
        return True

    rule = alert.get("rule") or {}
    groups = rule.get("groups") or []
    if isinstance(groups, list) and PROGRAM_NAME in groups:
        return True

    loc = alert.get("location")
    if isinstance(loc, str) and PROGRAM_NAME in loc:
        return True

    return False

IP_KEYS = [
    "srcip", "dstip",
    "src_ip", "dst_ip",
    "source_ip", "destination_ip",
    "source.ip", "destination.ip",
    "client.ip", "server.ip",
    "network.client.ip", "network.destination.ip",
    "observer.ip", "host.ip",
]

DOMAIN_KEYS = [
    "domain",
    "dns.question.name", "dns.question",
    "queryName", "query_name",
    "host.name",
]

URL_KEYS = [
    "url", "urls",
    "http.url", "request.url",
]

HASH_KEYS = [
    "md5", "sha1", "sha256",
    "md5_after", "sha1_after", "sha256_after",
    "hashes",
]

def _candidate_add(map_obj: dict, indicator: str, field_path: str):
    if not indicator:
        return
    if indicator not in map_obj:
        map_obj[indicator] = field_path

def extract_candidates_with_fields(alert: dict):
    ips_map, domains_map, urls_map, hashes_map = {}, {}, {}, {}

    scopes = [("root", alert)]
    for k in ("data", "syscheck", "network", "dns", "http", "win"):
        v = alert.get(k)
        if isinstance(v, dict):
            scopes.append((k, v))
        if k == "win" and isinstance(v, dict) and isinstance(v.get("eventdata"), dict):
            scopes.append(("win.eventdata", v["eventdata"]))

    def collect(keys, normalize_fn, target_map):
        for scope_name, sc in scopes:
            if not isinstance(sc, dict):
                continue
            for k in keys:
                v = deep_get(sc, k) if "." in k else sc.get(k)
                if v is None:
                    continue

                field_path = f"{k}" if scope_name == "root" else f"{scope_name}.{k}"

                if isinstance(v, list):
                    for it in v:
                        if isinstance(it, str) and it.strip():
                            ind = normalize_fn(it.strip())
                            _candidate_add(target_map, ind, field_path)
                elif isinstance(v, str) and v.strip():
                    ind = normalize_fn(v.strip())
                    _candidate_add(target_map, ind, field_path)

    collect(IP_KEYS, lambda s: s.split("|", 1)[0].strip(), ips_map)
    collect(DOMAIN_KEYS, lambda s: normalize_domain(s), domains_map)
    collect(URL_KEYS, lambda s: s, urls_map)
    collect(HASH_KEYS, lambda s: s, hashes_map)

    texts = []
    if isinstance(alert.get("full_log"), str) and alert["full_log"]:
        texts.append(("full_log", alert["full_log"]))
    for t in deep_collect_strings(alert):
        texts.append(("regex_scan", t))

    for origin, t in texts:
        for ip in RE_IPV4.findall(t):
            _candidate_add(ips_map, ip, f"{origin}.ip")
        for u in RE_URL.findall(t):
            _candidate_add(urls_map, u, f"{origin}.url")
        for d in RE_DOMAIN.findall(t):
            _candidate_add(domains_map, normalize_domain(d), f"{origin}.domain")
        for h in RE_SHA256.findall(t):
            _candidate_add(hashes_map, h, f"{origin}.sha256")
        for h in RE_SHA1.findall(t):
            _candidate_add(hashes_map, h, f"{origin}.sha1")
        for h in RE_MD5.findall(t):
            _candidate_add(hashes_map, h, f"{origin}.md5")

    expanded_hashes = {}
    for raw, field_path in list(hashes_map.items()):
        up = raw.upper()
        if "SHA256=" in up or "SHA1=" in up or "MD5=" in up:
            for hh in RE_SHA256.findall(raw):
                _candidate_add(expanded_hashes, hh, field_path)
            for hh in RE_SHA1.findall(raw):
                _candidate_add(expanded_hashes, hh, field_path)
            for hh in RE_MD5.findall(raw):
                _candidate_add(expanded_hashes, hh, field_path)
        else:
            _candidate_add(expanded_hashes, raw, field_path)

    ips_map = {k: v for k, v in ips_map.items() if k}
    domains_map = {k: v for k, v in domains_map.items() if k and "." in k}
    urls_map = {k: v for k, v in urls_map.items() if k}

    hashes_map = {}
    for h, fp in expanded_hashes.items():
        if isinstance(h, str) and h.strip():
            hashes_map[h.strip().lower()] = fp

    return ips_map, domains_map, urls_map, hashes_map

def lookup_ip(ip: str):
    if not db_exists(IPS_DB_PATH):
        return None
    with sqlite3.connect(IPS_DB_PATH) as c:
        row = c.execute(
            "SELECT indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category "
            "FROM ips WHERE indicator=?",
            (ip,),
        ).fetchone()
    if not row:
        return None
    indicator, source, updated_at, event_id, attr_id, mtype, mcat = row
    return {
        "indicator": indicator,
        "source": source,
        "updated_at": updated_at,
        "misp_event_id": event_id,
        "misp_attribute_id": attr_id,
        "misp_type": mtype,
        "misp_category": mcat,
    }

def hash_type(h: str):
    if RE_SHA256.fullmatch(h):
        return "sha256"
    if RE_SHA1.fullmatch(h):
        return "sha1"
    if RE_MD5.fullmatch(h):
        return "md5"
    return None

def lookup_hash(h: str):
    ht = hash_type(h)
    if not ht or not db_exists(HASHES_DB_PATH):
        return None
    with sqlite3.connect(HASHES_DB_PATH) as c:
        row = c.execute(
            "SELECT indicator, type, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category "
            "FROM hashes WHERE indicator=? AND type=?",
            (h.lower(), ht),
        ).fetchone()
    if not row:
        return None
    indicator, htype, source, updated_at, event_id, attr_id, mtype, mcat = row
    return {
        "indicator": indicator,
        "type": htype,
        "source": source,
        "updated_at": updated_at,
        "misp_event_id": event_id,
        "misp_attribute_id": attr_id,
        "misp_type": mtype,
        "misp_category": mcat,
    }

def lookup_domain(d: str):
    if not db_exists(DOMAINS_DB_PATH):
        return None
    d = normalize_domain(d)
    with sqlite3.connect(DOMAINS_DB_PATH) as c:
        row = c.execute(
            "SELECT indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category "
            "FROM domains WHERE indicator=?",
            (d,),
        ).fetchone()
    if not row:
        return None
    indicator, source, updated_at, event_id, attr_id, mtype, mcat = row
    return {
        "indicator": indicator,
        "source": source,
        "updated_at": updated_at,
        "misp_event_id": event_id,
        "misp_attribute_id": attr_id,
        "misp_type": mtype,
        "misp_category": mcat,
    }

def lookup_url(u: str):
    if not db_exists(URLS_DB_PATH):
        return None
    u = (u or "").strip()
    with sqlite3.connect(URLS_DB_PATH) as c:
        row = c.execute(
            "SELECT indicator, source, updated_at, misp_event_id, misp_attribute_id, misp_type, misp_category "
            "FROM urls WHERE indicator=?",
            (u,),
        ).fetchone()
    if not row:
        return None
    indicator, source, updated_at, event_id, attr_id, mtype, mcat = row
    return {
        "indicator": indicator,
        "source": source,
        "updated_at": updated_at,
        "misp_event_id": event_id,
        "misp_attribute_id": attr_id,
        "misp_type": mtype,
        "misp_category": mcat,
    }

def main():
    if len(sys.argv) < 2:
        sys.exit(0)

    alert_path = sys.argv[1]
    try:
        with open(alert_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception:
        sys.exit(0)

    if is_own_event(alert):
        sys.exit(0)

    agent = alert.get("agent") or {"id": "000", "name": "unknown", "ip": "any"}

    ips_map, domains_map, urls_map, hashes_map = extract_candidates_with_fields(alert)

    ip_hit = None
    hash_hit = None
    domain_hit = None
    url_hit = None

    ip_count = 0
    hash_count = 0
    domain_count = 0
    url_count = 0

    matched_ips = set()
    matched_hashes = set()
    matched_domains = set()
    matched_urls = set()

    matched_field = {}

    for ip in list(ips_map.keys())[:MAX_LOOKUPS_PER_TYPE]:
        r = lookup_ip(ip)
        if r:
            ip_count += 1
            matched_ips.add(ip)
            if ip_hit is None:
                ip_hit = dict(r)
                ip_hit["field_matched"] = ips_map.get(ip, "unknown")
                matched_field["ip"] = ip_hit["field_matched"]

    for h in list(hashes_map.keys())[:MAX_LOOKUPS_PER_TYPE]:
        r = lookup_hash(h)
        if r:
            hash_count += 1
            matched_hashes.add(h)
            if hash_hit is None:
                hash_hit = dict(r)
                hash_hit["field_matched"] = hashes_map.get(h, "unknown")
                matched_field["hash"] = hash_hit["field_matched"]

    for d in list(domains_map.keys())[:MAX_LOOKUPS_PER_TYPE]:
        r = lookup_domain(d)
        if r:
            domain_count += 1
            matched_domains.add(d)
            if domain_hit is None:
                domain_hit = dict(r)
                domain_hit["field_matched"] = domains_map.get(d, "unknown")
                matched_field["domain"] = domain_hit["field_matched"]

    for u in list(urls_map.keys())[:MAX_LOOKUPS_PER_TYPE]:
        r = lookup_url(u)
        if r:
            url_count += 1
            matched_urls.add(u)
            if url_hit is None:
                url_hit = dict(r)
                url_hit["field_matched"] = urls_map.get(u, "unknown")
                matched_field["url"] = url_hit["field_matched"]

    total = ip_count + hash_count + domain_count + url_count
    if total == 0 and SKIP_NO_MATCH:
        sys.exit(0)

    hit_obj = {}
    if ip_hit:
        hit_obj["ip"] = ip_hit
    if hash_hit:
        hit_obj["hash"] = hash_hit
    if domain_hit:
        hit_obj["domain"] = domain_hit
    if url_hit:
        hit_obj["url"] = url_hit

    hit_counts = {}
    if ip_count:
        hit_counts["ip"] = ip_count
    if hash_count:
        hit_counts["hash"] = hash_count
    if domain_count:
        hit_counts["domain"] = domain_count
    if url_count:
        hit_counts["url"] = url_count

    payload = {
        "integration": PROGRAM_NAME,
        "timestamp": now_iso(),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "original": {
            "alert_id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "rule_id": (alert.get("rule") or {}).get("id"),
            "rule_desc": (alert.get("rule") or {}).get("description"),
        },
        "ioc": {
            "matched": total,
            "hit_counts": hit_counts,
            "hit": hit_obj
        },
        "tags": tags_map()
    }

    extracted = {}
    if matched_ips:
        extracted["ips"] = to_flag_map(matched_ips)
    if matched_hashes:
        extracted["hashes"] = to_flag_map(matched_hashes)
    if matched_domains:
        extracted["domains"] = to_flag_map(matched_domains)
    if matched_urls:
        extracted["urls"] = to_flag_map(matched_urls)
    if extracted:
        payload["extracted"] = extracted

    send_event(payload, agent)

if __name__ == "__main__":
    main()
