#!/usr/bin/env python3
"""CrowdSec Dashboard – kleiner Proxy/Aggregator für die CrowdSec Local API (LAPI).

Nur Python-Standardbibliothek. Konfiguration ausschließlich über Umgebungsvariablen
(siehe .env.example). Der Browser spricht nie direkt mit der LAPI: Zugangsdaten
bleiben auf dem Server, die Oberfläche bekommt nur aufbereitete JSON-Daten.
"""
import base64
import hmac
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def env(name, default=""):
    return os.environ.get(name, default).strip()


def env_bool(name):
    return env(name).lower() in ("1", "true", "yes", "on")


LAPI_URL = env("LAPI_URL", "http://127.0.0.1:8080").rstrip("/")
MACHINE_ID = env("LAPI_MACHINE_ID")
MACHINE_PASSWORD = env("LAPI_MACHINE_PASSWORD")
BOUNCER_KEY = env("LAPI_BOUNCER_KEY")
INSECURE_TLS = env_bool("LAPI_INSECURE_TLS")
LISTEN_HOST = env("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(env("LISTEN_PORT", "3000"))
DASH_USER = env("DASHBOARD_USER", "admin")
DASH_PASSWORD = env("DASHBOARD_PASSWORD")
DEMO = env_bool("DEMO")
ALERT_LIMIT = int(env("ALERT_LIMIT", "5000"))
CACHE_TTL = int(env("CACHE_TTL", "20"))
HOME_LAT = float(env("HOME_LAT", "50.11"))   # Standort des eigenen Servers auf dem Globus (Default: Frankfurt)
HOME_LON = float(env("HOME_LON", "8.68"))
HOME_LABEL = env("HOME_LABEL", "HOME")
# Fallback-Geocoding für IPs ohne Koordinaten: "" (aus) oder "ipapi" (sendet IPs an ip-api.com!)
GEO_FALLBACK = env("GEO_FALLBACK").lower()

# Zeitraum -> (Stunden, Bucket-Größe in Sekunden für die Zeitachse)
RANGES = {"24h": (24, 3600), "7d": (168, 4 * 3600), "30d": (720, 86400)}
REMOTE_ORIGINS = ("CAPI", "lists")

STATIC_DIR = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
}
STATIC_FILES = {p.name: p for p in STATIC_DIR.iterdir() if p.suffix in CONTENT_TYPES} if STATIC_DIR.is_dir() else {}


# --------------------------------------------------------------------------- helpers

_FRACTION = re.compile(r"(\.\d{3})\d+")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}


def norm_time(value):
    """LAPI liefert Nanosekunden – auf Millisekunden kürzen, damit Browser parsen können."""
    return _FRACTION.sub(r"\1", value) if value else ""


def go_duration_seconds(value):
    """Go-Dauer wie '3h59m12.5s' oder '-1h2m' in Sekunden umrechnen."""
    if not value:
        return None
    total = sum(float(n) * _UNITS[u] for n, u in _DURATION.findall(value))
    return int(-total if value.startswith("-") else total)


def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- LAPI client


class LapiError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class Lapi:
    def __init__(self):
        self._token = None
        self._token_valid_until = 0.0
        self._lock = threading.Lock()
        self._ctx = ssl._create_unverified_context() if INSECURE_TLS else None

    def _request(self, method, path, headers=None, body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Accept": "application/json", "User-Agent": "crowdsec-dashboard/1.0"}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(LAPI_URL + path, data=data, headers=hdrs, method=method)
        endpoint = path.split("?")[0]
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode(errors="replace").strip()
            raise LapiError(f"LAPI {method} {endpoint} antwortet mit HTTP {e.code}: {detail}", e.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise LapiError(f"LAPI unter {LAPI_URL} nicht erreichbar: {reason}") from None
        if not raw.strip():
            return None
        return json.loads(raw)

    def _login(self):
        res = self._request(
            "POST",
            "/v1/watchers/login",
            body={"machine_id": MACHINE_ID, "password": MACHINE_PASSWORD, "scenarios": []},
        )
        self._token = res["token"]
        valid = time.time() + 30 * 60
        try:
            expire = datetime.fromisoformat(norm_time(res.get("expire", "")).replace("Z", "+00:00"))
            valid = expire.timestamp()
        except ValueError:
            pass
        self._token_valid_until = valid - 60

    def alerts(self, hours):
        query = urllib.parse.urlencode({"since": f"{hours}h", "limit": ALERT_LIMIT, "include_capi": "false"})
        for attempt in (0, 1):
            with self._lock:
                if not self._token or time.time() >= self._token_valid_until:
                    self._login()
                token = self._token
            try:
                return self._request("GET", f"/v1/alerts?{query}", headers={"Authorization": f"Bearer {token}"}) or []
            except LapiError as e:
                if e.code == 401 and attempt == 0:
                    with self._lock:
                        self._token = None
                    continue
                raise
        return []

    def decisions(self):
        return self._request("GET", "/v1/decisions", headers={"X-Api-Key": BOUNCER_KEY}) or []


# --------------------------------------------------------------------------- aggregation


def compact_alert(a):
    decisions = a.get("decisions") or []
    if any(d.get("origin") in REMOTE_ORIGINS for d in decisions):
        return None  # Community-/Blocklisten-Importe sind keine Angriffe auf diesen Server
    src = a.get("source") or {}
    first = decisions[0] if decisions else {}
    lat, lon = src.get("latitude"), src.get("longitude")
    has_geo = isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and not (lat == 0 and lon == 0)
    return {
        "id": a.get("id"),
        "t": norm_time(a.get("start_at") or a.get("created_at")),
        "ip": src.get("ip") or src.get("value") or "",
        "scope": src.get("scope") or "",
        "cn": (src.get("cn") or "").upper(),
        "as": src.get("as_name") or "",
        "asn": str(src.get("as_number") or ""),
        "lat": round(lat, 3) if has_geo else None,
        "lon": round(lon, 3) if has_geo else None,
        "geo": "crowdsec" if has_geo else None,
        "scenario": a.get("scenario") or "",
        "events": a.get("events_count") or 0,
        "machine": a.get("machine_id") or "",
        "sim": bool(a.get("simulated")),
        "decision": first.get("type") or "",
        "remaining": go_duration_seconds(first.get("duration")),
    }


def summarize_decisions(decisions):
    by_origin, by_type, local = Counter(), Counter(), []
    for d in decisions:
        origin = d.get("origin") or "unbekannt"
        by_origin[origin] += 1
        by_type[d.get("type") or "?"] += 1
        if origin not in REMOTE_ORIGINS:
            local.append(
                {
                    "value": d.get("value") or "",
                    "scope": d.get("scope") or "",
                    "type": d.get("type") or "",
                    "origin": origin,
                    "scenario": d.get("scenario") or "",
                    "remaining": go_duration_seconds(d.get("duration")),
                    "sim": bool(d.get("simulated")),
                }
            )
    local.sort(key=lambda x: -(x["remaining"] or 0))
    return {
        "total": len(decisions),
        "by_origin": by_origin.most_common(),
        "by_type": by_type.most_common(),
        "local": local[:3000],
        "local_total": len(local),
    }


# --------------------------------------------------------------------------- geocoding fallback

_geo_cache = {}  # ip -> (lat, lon) | None


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def geo_fill(alerts, warnings):
    """Ergänzt fehlende Koordinaten über ip-api.com (nur wenn GEO_FALLBACK=ipapi)."""
    if GEO_FALLBACK != "ipapi":
        return
    if len(_geo_cache) > 50000:
        _geo_cache.clear()
    missing = []
    for a in alerts:
        ip = a["ip"]
        if a["lat"] is None and ip not in _geo_cache and ip not in missing and _is_public(ip):
            missing.append(ip)
    for i in range(0, min(len(missing), 300), 100):  # max. 3 Batch-Anfragen pro Abruf (Limit: 15/min)
        chunk = missing[i:i + 100]
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,query,lat,lon", data=json.dumps(chunk).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "crowdsec-dashboard/1.0"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            warnings.append(f"Geocoding-Fallback (ip-api.com) fehlgeschlagen: {getattr(e, 'reason', e)}")
            break
        for r in results:
            ok = r.get("status") == "success"
            _geo_cache[r.get("query")] = (r["lat"], r["lon"]) if ok else None
    for a in alerts:
        hit = _geo_cache.get(a["ip"]) if a["lat"] is None else None
        if hit:
            a["lat"], a["lon"], a["geo"] = round(hit[0], 3), round(hit[1], 3), "ipapi"


# --------------------------------------------------------------------------- demo data

DEMO_SCENARIOS = [
    ("crowdsecurity/ssh-bf", 30), ("crowdsecurity/http-probing", 22), ("crowdsecurity/http-crawl-non_statics", 12),
    ("crowdsecurity/ssh-slow-bf", 9), ("crowdsecurity/http-sensitive-files", 8), ("crowdsecurity/http-bad-user-agent", 6),
    ("crowdsecurity/http-admin-interface-probing", 5), ("crowdsecurity/http-wordpress_scan", 4),
    ("crowdsecurity/http-cve-2021-41773", 2), ("crowdsecurity/nginx-req-limit-exceeded", 2),
]
DEMO_NETWORKS = [  # (Land, ASN, Netzname, Gewicht, Standorte)
    ("CN", "4134", "CHINANET-BACKBONE", 18, [(39.9, 116.4), (31.2, 121.5), (23.1, 113.3), (30.6, 104.1)]),
    ("US", "14061", "DIGITALOCEAN-ASN", 14, [(40.7, -74.0), (37.8, -122.4)]),
    ("NL", "14061", "DIGITALOCEAN-ASN", 6, [(52.4, 4.9)]),
    ("RU", "49505", "OOO Network of data-centers Selectel", 8, [(55.8, 37.6), (59.9, 30.3)]),
    ("DE", "24940", "Hetzner Online GmbH", 7, [(50.5, 12.4), (49.5, 11.1)]),
    ("US", "16509", "AMAZON-02", 9, [(39.0, -77.5), (45.8, -119.7), (40.0, -83.0)]),
    ("VN", "45899", "VNPT Corp", 6, [(21.0, 105.8), (10.8, 106.7)]),
    ("BR", "28573", "Claro NXT Telecomunicacoes", 5, [(-23.5, -46.6), (-22.9, -43.2)]),
    ("IN", "9829", "National Internet Backbone", 5, [(19.1, 72.9), (28.6, 77.2), (13.1, 80.3)]),
    ("KR", "4766", "Korea Telecom", 4, [(37.6, 127.0), (35.2, 129.1)]),
    ("SG", "135377", "UCLOUD INFORMATION", 4, [(1.35, 103.8)]),
    ("FR", "16276", "OVH SAS", 4, [(50.7, 3.2), (51.0, 2.1)]),
    ("GB", "14061", "DIGITALOCEAN-ASN", 2, [(51.5, -0.1)]),
    ("ID", "7713", "PT Telekomunikasi Indonesia", 3, [(-6.2, 106.8), (-7.3, 112.7)]),
]
_DEMO_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")  # Dokumentations-Netze, keine echten Angreifer


def _weighted(rng, items, w=-1):
    return rng.choices(items, weights=[i[w] for i in items])[0]


def demo_payload(range_key):
    hours, _ = RANGES[range_key]
    rng = random.Random(int(time.time() // 3600))  # stabil innerhalb einer Stunde
    now = datetime.now(timezone.utc)
    pool = []
    for i in range(420):
        cn, asn, as_name, _, cities = _weighted(rng, DEMO_NETWORKS, 3)
        lat, lon = rng.choice(cities)
        lat, lon = round(lat + rng.uniform(-0.4, 0.4), 3), round(lon + rng.uniform(-0.4, 0.4), 3)
        geo = rng.random() > 0.04  # ein paar ohne Koordinaten -> Fallback Landesmitte
        pool.append((f"{_DEMO_PREFIXES[i % 3]}{i // 3 + 1}", cn, asn, as_name, lat if geo else None, lon if geo else None))
    weights = [1 / (i + 1) ** 0.8 for i in range(len(pool))]

    alerts = []
    for h in range(hours):
        t_hour = now - timedelta(hours=h)
        local_hour = (t_hour.hour + 1) % 24
        rate = 4 + 3 * (1 if 1 <= local_hour <= 7 else 0) + rng.random() * 3
        if 30 <= h <= 33 or 140 <= h <= 142:  # zwei Angriffswellen
            rate *= 4
        for _ in range(int(rate)):
            ip, cn, asn, as_name, lat, lon = rng.choices(pool, weights=weights)[0]
            scenario = _weighted(rng, DEMO_SCENARIOS)[0]
            ts = t_hour - timedelta(seconds=rng.randint(0, 3599))
            age = (now - ts).total_seconds()
            alerts.append(
                {
                    "id": len(alerts) + 1, "t": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                    "ip": ip, "scope": "Ip", "cn": cn, "as": as_name, "asn": asn, "scenario": scenario,
                    "lat": lat, "lon": lon, "geo": "crowdsec" if lat is not None else None,
                    "events": rng.randint(5, 60) if "bf" in scenario else rng.randint(3, 25),
                    "machine": rng.choice(["web-01", "web-01", "mail-01"]), "sim": False,
                    "decision": "ban", "remaining": int(4 * 3600 - age),
                }
            )
    alerts.sort(key=lambda a: a["t"], reverse=True)
    truncated = len(alerts) > ALERT_LIMIT
    alerts = alerts[:ALERT_LIMIT]

    local, seen = [], set()
    for a in alerts:
        if a["remaining"] > 0 and a["ip"] not in seen:
            seen.add(a["ip"])
            local.append({"value": a["ip"], "scope": "Ip", "type": "ban", "origin": "crowdsec",
                          "scenario": a["scenario"], "remaining": a["remaining"], "sim": False})
    manual = [("198.51.100.250", 160 * 3600), ("203.0.113.0/24", 700 * 3600), ("192.0.2.77", 20 * 3600)]
    for value, rem in manual:
        local.append({"value": value, "scope": "Range" if "/" in value else "Ip", "type": "ban",
                      "origin": "cscli", "scenario": "manual 'ban' from 'admin'", "remaining": rem, "sim": False})
    local.append({"value": "192.0.2.201", "scope": "Ip", "type": "captcha", "origin": "crowdsec",
                  "scenario": "crowdsecurity/http-crawl-non_statics", "remaining": 2 * 3600, "sim": False})
    local.sort(key=lambda x: -x["remaining"])
    capi, lists = 15312, 2417
    by_type = Counter(d["type"] for d in local)
    by_type["ban"] += capi + lists
    by_origin = Counter(d["origin"] for d in local)
    by_origin.update({"CAPI": capi, "lists": lists})
    return {
        "alerts": alerts, "alerts_truncated": truncated,
        "decisions": {"total": len(local) + capi + lists, "by_origin": by_origin.most_common(),
                      "by_type": by_type.most_common(), "local": local, "local_total": len(local)},
        "warnings": [],
    }


# --------------------------------------------------------------------------- summary + cache

_lapi = Lapi()
_cache = {}
_cache_lock = threading.Lock()


def live_payload(range_key):
    hours, _ = RANGES[range_key]
    warnings, alerts, truncated, decisions = [], None, False, None
    errors = 0
    if MACHINE_ID and MACHINE_PASSWORD:
        try:
            raw = _lapi.alerts(hours)
            truncated = len(raw) >= ALERT_LIMIT
            alerts = [c for c in (compact_alert(a) for a in raw) if c]
            alerts.sort(key=lambda a: a["t"], reverse=True)
            geo_fill(alerts, warnings)
        except LapiError as e:
            warnings.append(f"Alerts konnten nicht geladen werden – {e}")
            errors += 1
    else:
        warnings.append("LAPI_MACHINE_ID / LAPI_MACHINE_PASSWORD fehlen – Alerts sind deaktiviert.")
    if BOUNCER_KEY:
        try:
            decisions = summarize_decisions(_lapi.decisions())
        except LapiError as e:
            warnings.append(f"Sperren konnten nicht geladen werden – {e}")
            errors += 1
    else:
        warnings.append("LAPI_BOUNCER_KEY fehlt – aktive Sperren sind deaktiviert.")
    if errors and alerts is None and decisions is None:
        raise LapiError(" · ".join(warnings))
    return {"alerts": alerts or [], "alerts_truncated": truncated, "decisions": decisions, "warnings": warnings}


def summary(range_key):
    with _cache_lock:
        hit = _cache.get(range_key)
        if hit and time.time() - hit[0] < CACHE_TTL:
            return hit[1]
        payload = demo_payload(range_key) if DEMO else live_payload(range_key)
        hours, bucket = RANGES[range_key]
        payload.update(
            {
                "generated_at": iso_now(), "range": range_key, "hours": hours, "bucket": bucket,
                "alert_limit": ALERT_LIMIT, "demo": DEMO,
                "home": {"lat": HOME_LAT, "lon": HOME_LON, "label": HOME_LABEL},
                "source": "demo" if DEMO else urllib.parse.urlsplit(LAPI_URL).netloc,
            }
        )
        _cache[range_key] = (time.time(), payload)
        return payload


# --------------------------------------------------------------------------- HTTP

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "crowdsec-dashboard"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}\n")

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), "application/json; charset=utf-8")

    def _authorized(self):
        if not DASH_PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        ok_user = hmac.compare_digest(user.encode(), DASH_USER.encode())
        ok_pass = hmac.compare_digest(password.encode(), DASH_PASSWORD.encode())
        return ok_user and ok_pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == "/healthz":
            return self._send(200, b"ok\n", "text/plain; charset=utf-8")
        if not self._authorized():
            return self._send(401, b"Anmeldung erforderlich\n", "text/plain; charset=utf-8",
                              {"WWW-Authenticate": 'Basic realm="CrowdSec Dashboard", charset="UTF-8"'})
        if path == "/api/summary":
            range_key = urllib.parse.parse_qs(parts.query).get("range", ["24h"])[0]
            if range_key not in RANGES:
                return self._send_json(400, {"error": "Unbekannter Zeitraum"})
            try:
                return self._send_json(200, summary(range_key))
            except LapiError as e:
                return self._send_json(502, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 – Fehler sichtbar machen statt Verbindung abzubrechen
                self.log_error("Interner Fehler: %r", e)
                return self._send_json(500, {"error": "Interner Fehler im Dashboard-Server"})
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        file = STATIC_FILES.get(name)
        if not file:
            return self._send(404, b"Nicht gefunden\n", "text/plain; charset=utf-8")
        return self._send(200, file.read_bytes(), CONTENT_TYPES[file.suffix])


def main():
    if not STATIC_FILES:
        sys.exit(f"Verzeichnis {STATIC_DIR} mit der Oberfläche fehlt.")
    if not DEMO and not ((MACHINE_ID and MACHINE_PASSWORD) or BOUNCER_KEY):
        sys.exit("Keine LAPI-Zugangsdaten gesetzt. LAPI_MACHINE_ID/LAPI_MACHINE_PASSWORD und/oder "
                 "LAPI_BOUNCER_KEY setzen – oder DEMO=1 zum Ausprobieren.")
    if not DASH_PASSWORD and LISTEN_HOST not in ("127.0.0.1", "localhost", "::1"):
        print("WARNUNG: Dashboard lauscht ohne Passwort auf einer externen Adresse. DASHBOARD_PASSWORD setzen!",
              file=sys.stderr)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    mode = "DEMO-Modus" if DEMO else f"LAPI {LAPI_URL}"
    print(f"CrowdSec Dashboard läuft auf http://{LISTEN_HOST}:{LISTEN_PORT} ({mode})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
