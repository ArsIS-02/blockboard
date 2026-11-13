#!/usr/bin/env python3
"""BlockBoard — пульт блокировки индикаторов компрометации (IOC).

Веб-интерфейс + исполнители: Keenetic RCI (reject-маршрут для IP,
статическая DNS-запись 0.0.0.0 для домена) и dry-run (только журнал).
Каждое действие уходит событием в Graylog по GELF UDP.

Маршруты:
  GET  /                       — страница (нужна сессия)
  GET  /login                  — форма входа
  POST /api/login              — {user, password}
  POST /api/logout
  GET  /api/blocks             — активные блокировки
  POST /api/blocks             — {indicator, reason, source, ttl_hours}
  POST /api/blocks/<id>/unblock
  POST /api/blocks/<id>/extend — {hours}
  GET  /api/history            — журнал действий
  GET  /api/settings           — настройки (пароль роутера маскируется)
  POST /api/settings           — {router_host, router_user, router_pass, mode}
  POST /api/test-router        — проверка связи с Keenetic (show version)
  GET  /favicon.svg, /logo.svg

ENV: BB_PORT (8098), BB_USER, BB_PASS, BB_DB, GELF_HOST, GELF_PORT
"""
import base64, csv, gzip, hashlib, io, ipaddress, json, os, re, secrets, socket, sqlite3
import ssl, threading, time, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("BB_PORT", "8098"))
BB_USER = os.environ.get("BB_USER", "admin")
BB_PASS = os.environ.get("BB_PASS", "admin")
DB_PATH = os.environ.get("BB_DB", "/data/blockboard.db")
GELF_HOST = os.environ.get("GELF_HOST", "host.containers.internal")
GELF_PORT = int(os.environ.get("GELF_PORT", "12206"))
HOSTNAME = socket.gethostname()
ROOT = Path(__file__).resolve().parent

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

SESSIONS = {}          # token -> expiry ts
SESSION_TTL = 12 * 3600
DOMAIN_RE = re.compile(r"^([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.I)

# ---------------------------------------------------------------- БД

def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS blocks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT NOT NULL, itype TEXT NOT NULL,
        reason TEXT DEFAULT '', source TEXT DEFAULT '',
        created REAL NOT NULL, expires REAL,
        active INTEGER NOT NULL DEFAULT 1,
        status TEXT DEFAULT '', executor_msg TEXT DEFAULT '')""")
    con.execute("""CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL, action TEXT NOT NULL, indicator TEXT NOT NULL,
        actor TEXT DEFAULT '', detail TEXT DEFAULT '')""")
    con.execute("""CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY, value TEXT DEFAULT '')""")
    con.commit()
    return con


def get_setting(con, key, default=""):
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(con, key, value):
    con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value))

# ---------------------------------------------------------------- Graylog

GL_API = os.environ.get("BB_GRAYLOG_API", "https://graylog.apps.monitoring.test/api")
GL_USER = os.environ.get("BB_GRAYLOG_USER", "")
GL_PASS = os.environ.get("BB_GRAYLOG_PASS", "")


def geo_stats(days: int = 30) -> dict:
    """Агрегация блокировок по странам/городам/причинам из журнала Graylog.

    Гео-поля (indicator_country_code, indicator_city_name) добавляет
    GeoIP-пайплайн Graylog на событиях tool:blockboard — читаем их оттуда.
    """
    if not (GL_USER and GL_PASS):
        return {"ok": False, "error": "не заданы BB_GRAYLOG_USER/BB_GRAYLOG_PASS"}
    days = max(1, min(days, 365))
    fields = "timestamp,action,indicator,reason,source,indicator_country_code,indicator_city_name"
    q = urllib.parse.quote("tool:blockboard AND action:block")
    url = (f"{GL_API}/search/universal/relative?query={q}"
           f"&range={days * 86400}&limit=10000&fields={fields}")
    req = urllib.request.Request(url)
    tok = base64.b64encode(f"{GL_USER}:{GL_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {tok}")
    req.add_header("X-Requested-By", "blockboard")
    try:
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
            raw = r.read().decode("utf-8", "replace")
    except Exception as e:
        return {"ok": False, "error": f"Graylog API: {e}"}
    countries: dict[str, dict] = {}
    reasons: dict[str, int] = {}
    total = no_geo = 0
    for row in csv.DictReader(io.StringIO(raw)):
        total += 1
        cc = (row.get("indicator_country_code") or "").strip().upper()
        reason = (row.get("reason") or "").strip() or "—"
        reasons[reason] = reasons.get(reason, 0) + 1
        if not cc:
            no_geo += 1
            continue
        c = countries.setdefault(cc, {"count": 0, "cities": {}})
        c["count"] += 1
        city = (row.get("indicator_city_name") or "").strip()
        if city and city != "N/A":
            c["cities"][city] = c["cities"].get(city, 0) + 1
    out_countries = [
        {"code": cc, "count": c["count"],
         "cities": sorted(c["cities"].items(), key=lambda kv: -kv[1])[:5]}
        for cc, c in sorted(countries.items(), key=lambda kv: -kv[1]["count"])]
    return {"ok": True, "days": days, "total": total, "no_geo": no_geo,
            "countries": out_countries,
            "reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:10]}


def send_gelf(short, level=5, **fields):
    try:
        msg = {"version": "1.1", "host": HOSTNAME, "short_message": short,
               "timestamp": time.time(), "level": level,
               "_tool": "blockboard", "_source_tool": "blockboard"}
        msg.update({f"_{k}": str(v) for k, v in fields.items()})
        data = gzip.compress(json.dumps(msg).encode())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data, (GELF_HOST, GELF_PORT))
        s.close()
    except Exception:
        pass


def log_history(con, action, indicator, actor, detail=""):
    con.execute("INSERT INTO history(ts,action,indicator,actor,detail) "
                "VALUES(?,?,?,?,?)", (time.time(), action, indicator, actor, detail))

# ---------------------------------------------------------------- Keenetic RCI

class KeeneticError(Exception):
    pass


class Keenetic:
    """RCI-клиент Keenetic NDMS (x-ndw2-interactive auth)."""

    def __init__(self, host, user, password, timeout=30):
        self.base = f"http://{host}"
        self.user, self.password, self.timeout = user, password, timeout
        self.cookie = None

    def _req(self, path, data=None, method=None):
        url = self.base + path
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            resp = urllib.request.urlopen(req, context=CTX, timeout=self.timeout)
            return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()
        except Exception as e:
            raise KeeneticError(f"роутер недоступен: {e}")

    def auth(self):
        status, headers, _ = self._req("/auth")
        if status == 200:
            return  # уже авторизованы
        challenge = headers.get("X-NDM-Challenge")
        realm = headers.get("X-NDM-Realm")
        cookie = None
        sc = headers.get("Set-Cookie", "")
        m = re.search(r"([^=;\s]+=[^;]+)", sc)
        if m:
            cookie = m.group(1)
        if not challenge or not realm or not cookie:
            raise KeeneticError("роутер не вернул challenge/realm (это точно Keenetic?)")
        md5 = hashlib.md5(f"{self.user}:{realm}:{self.password}".encode()).hexdigest()
        digest = hashlib.sha256((challenge + md5).encode()).hexdigest()
        self.cookie = cookie
        status, headers, _ = self._req("/auth", {"login": self.user, "password": digest})
        if status != 200:
            raise KeeneticError(f"аутентификация отклонена (HTTP {status}) — проверьте логин/пароль")

    def rci(self, *commands):
        self.auth()
        status, _, body = self._req("/rci/", list(commands))
        if status != 200:
            raise KeeneticError(f"RCI вернул HTTP {status}: {body[:200]!r}")
        result = json.loads(body or b"[]")
        errors = []
        def walk(o):
            if isinstance(o, dict):
                if o.get("status") == "error":
                    errors.append(o.get("message", "?"))
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(result)
        if errors:
            raise KeeneticError("; ".join(errors)[:300])
        return result

    def get(self, path):
        self.auth()
        status, _, body = self._req(path)
        if status != 200:
            raise KeeneticError(f"GET {path}: HTTP {status}")
        return json.loads(body or b"{}")

    def show_version(self):
        r = self.rci({"show": {"version": {}}})
        v = (r[0] if r else {}).get("show", {}).get("version", {})
        return f"NDMS {v.get('title', '?')} (релиз {v.get('release', '?')})"

    # ---- ACL BlockBoard на файрволе (интерфейс Bridge0, направление in) ----

    ACL = "BlockBoard"
    LAN_IFACE = "Bridge0"

    def _acl_rules(self):
        """Текущие правила ACL BlockBoard на роутере."""
        try:
            rules = self.get("/rci/access-list")
        except KeeneticError:
            return []
        return [r for r in rules
                if r.get("acl") == self.ACL and "action" in r]

    @staticmethod
    def _rule(indicator, action="deny", no=False):
        r = {"acl": Keenetic.ACL, "action": action, "protocol": "ip",
             "source": "0.0.0.0", "source-mask": "0.0.0.0",
             "destination": indicator,
             "destination-mask": "255.255.255.255" if indicator != "0.0.0.0" else "0.0.0.0"}
        if no:
            r["no"] = True
        return r

    def _running_config(self):
        self.auth()
        status, _, body = self._req("/ci/running-config.txt")
        if status != 200:
            raise KeeneticError(f"running-config: HTTP {status}")
        return body.decode(errors="replace")

    def _ensure_attached(self):
        cfg = self._running_config()
        i = cfg.find(f"interface {self.LAN_IFACE}")
        if i < 0:
            raise KeeneticError(f"интерфейс {self.LAN_IFACE} не найден на роутере")
        block = cfg[i:cfg.find("\n!", i) if cfg.find("\n!", i) > 0 else len(cfg)]
        if f"ip access-group {self.ACL} in" not in block:
            self.rci({"interface": {self.LAN_IFACE: {"ip": {"access-group":
                          [{"acl": self.ACL, "direction": "in"}]}}}})

    def reconcile_acl(self, ips, save=True):
        """Пересобирает ACL из списка активных IP: deny-правила, затем permit-all.

        Порядок критичен: роутер дописывает новые правила в конец,
        поэтому ACL каждый раз пересоздаётся целиком.
        save=False — не сохранять startup-config (для автоматических
        синхронизаций, чтобы не шуметь «configuration saved» в syslog)."""
        self._ensure_attached()
        cmds = []
        for r in self._acl_rules():
            cmds.append({"access-list": [{
                "acl": self.ACL, "action": r["action"], "protocol": r["protocol"],
                "source": r["source"], "source-mask": r["source-mask"],
                "destination": r["destination"],
                "destination-mask": r["destination-mask"], "no": True}]})
        for ip in sorted(ips):
            cmds.append({"access-list": [self._rule(ip)]})
        cmds.append({"access-list": [self._rule("0.0.0.0", "permit")]})
        if save:
            cmds.append({"system": {"configuration": {"save": {}}}})
        self.rci(*cmds)

    def save_config(self):
        """Явное сохранение startup-config на роутере."""
        self.rci({"system": {"configuration": {"save": {}}}})

    # ---- домены: статические DNS-записи 0.0.0.0 ----

    def block_domain(self, domain, save=True):
        cmds = [{"ip": {"host": {"domain": domain, "address": "0.0.0.0"}}}]
        if save:
            cmds.append({"system": {"configuration": {"save": {}}}})
        self.rci(*cmds)

    def unblock_domain(self, domain, save=True):
        cmds = [{"ip": {"host": {"domain": domain, "no": True}}}]
        if save:
            cmds.append({"system": {"configuration": {"save": {}}}})
        self.rci(*cmds)

    def static_hosts(self):
        """Текущие статические DNS-записи роутера: {domain: [address,...]}."""
        try:
            hosts = self.get("/rci/ip/host")
        except KeeneticError:
            return {}
        out = {}
        items = hosts if isinstance(hosts, list) else [hosts]
        for h in items:
            if not isinstance(h, dict):
                continue
            d = (h.get("domain") or "").strip().lower()
            a = (h.get("address") or "").strip()
            if d:
                out.setdefault(d, []).append(a)
        return out


def detect_type(indicator):
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if DOMAIN_RE.match(indicator):
        return "domain"
    return None


def get_executor(con):
    """Возвращает (callable_block, callable_unblock, mode_label) или None для dry-run."""
    mode = get_setting(con, "mode", "dryrun")
    if mode == "keenetic":
        host = get_setting(con, "router_host")
        user = get_setting(con, "router_user", "admin")
        pw_b64 = get_setting(con, "router_pass")
        try:
            pw = base64.b64decode(pw_b64).decode() if pw_b64 else ""
        except Exception:
            pw = ""
        if host and pw:
            k = Keenetic(host, user, pw)
            return k, "keenetic"
    return None, "dryrun"


def apply_block(con, indicator, itype, save=True):
    """Блокировка. Для IP вызывать ПОСЛЕ записи в БД — ACL строится из БД.
    save=False — изменения действуют до перезагрузки роутера, но не пишутся
    в startup-config (автоматические прогоны feedpipe: 50 доменов за раз =
    50 «configuration saved» в syslog). Персистентность даёт дневной
    reconcile в sweeper()."""
    k, mode = get_executor(con)
    if not k:
        return True, "dry-run: действие записано, роутер не подключён"
    try:
        if itype == "domain":
            k.block_domain(indicator, save=save)
            return True, f"keenetic: {indicator} → 0.0.0.0 (DNS)"
        return sync_router_acl(con, k, save=save)
    except KeeneticError as e:
        return False, f"keenetic: ошибка — {e}"


def apply_unblock(con, indicator, itype, save=True):
    """Снятие блокировки. Для IP вызывать ПОСЛЕ обновления БД."""
    k, mode = get_executor(con)
    if not k:
        return True, "dry-run: действие записано, роутер не подключён"
    try:
        if itype == "domain":
            k.unblock_domain(indicator, save=save)
            return True, f"keenetic: {indicator} разблокирован (DNS)"
        return sync_router_acl(con, k, save=save)
    except KeeneticError as e:
        return False, f"keenetic: ошибка — {e}"


def sync_router_acl(con, k, save=True):
    ips = [r["indicator"] for r in con.execute(
        "SELECT indicator FROM blocks WHERE active=1 AND itype='ip'").fetchall()]
    k.reconcile_acl(ips, save=save)
    return True, f"keenetic: ACL обновлён, активных IP-блокировок: {len(ips)}"


def reconcile_domains(con, k):
    """Полное согласование доменов: догоняет DNS-записи роутера до БД.

    Добавляет записи для активных блокировок, которых нет на роутере
    (например, созданных без save до перезагрузки), и убирает записи
    0.0.0.0 для доменов, которых уже нет в активных. Возвращает сводку."""
    active = {r["indicator"] for r in con.execute(
        "SELECT indicator FROM blocks WHERE active=1 AND itype='domain'").fetchall()}
    current = k.static_hosts()
    added = removed = 0
    for d in sorted(active):
        if "0.0.0.0" not in current.get(d, []):
            k.block_domain(d, save=False)
            added += 1
    for d, addrs in current.items():
        if d not in active and addrs and all(a == "0.0.0.0" for a in addrs):
            k.unblock_domain(d, save=False)
            removed += 1
    return added, removed

# ---------------------------------------------------------------- фон: снятие по TTL

YEKT = timezone(timedelta(hours=5))          # Asia/Yekaterinburg, без DST
DAILY_SAVE_MINUTES = range(17, 28)           # окно 04:17–04:27 местного
_daily_save_state = {"day": None}            # дата последнего дневного сохранения


def daily_reconcile(con):
    """Раз в сутки (04:17–04:27 по Екатеринбургу): полное согласование роутера
    с БД (домены + IP-ACL) и ОДНО сохранение startup-config.

    Именно этот save делает персистентными автоматические блокировки feedpipe,
    которые применяются без save. Один save в день вместо ~50 в час."""
    k, mode = get_executor(con)
    if not k:
        return
    try:
        added, removed = reconcile_domains(con, k)
        ok, msg = sync_router_acl(con, k, save=False)
        k.save_config()
        detail = f"домены +{added}/-{removed}; {msg}"
        log_history(con, "daily-save", "-", "blockboard", detail)
        send_gelf("BlockBoard: дневное согласование и сохранение конфигурации",
                  action="daily-save", result=detail)
        print(f"daily reconcile: {detail}")
    except KeeneticError as e:
        log_history(con, "daily-save", "-", "blockboard", f"ошибка: {e}")
        send_gelf(f"BlockBoard: ошибка дневного сохранения — {e}", level=3,
                  action="daily-save", result=str(e))


def sweeper():
    while True:
        time.sleep(60)
        try:
            con = db()
            now = time.time()
            rows = con.execute("SELECT * FROM blocks WHERE active=1 AND expires IS NOT NULL "
                               "AND expires<?", (now,)).fetchall()
            if rows:
                for r in rows:
                    con.execute("UPDATE blocks SET active=0, status='expired' WHERE id=?", (r["id"],))
                con.commit()
                # сначала домены (индивидуально), потом один reconcile ACL для IP
                # save=False: снятия по TTL — автоматические, не пишем startup-config
                k, mode = get_executor(con)
                for r in rows:
                    if r["itype"] == "domain":
                        ok, msg = apply_unblock(con, r["indicator"], r["itype"], save=False)
                    else:
                        ok, msg = (apply_unblock(con, r["indicator"], r["itype"], save=False)
                                   if mode != "dryrun" else
                                   (True, "dry-run: действие записано, роутер не подключён"))
                    con.execute("UPDATE blocks SET status=?, executor_msg=? WHERE id=?",
                                ("expired" if ok else "expire-error", msg, r["id"]))
                    log_history(con, "expire", r["indicator"], "blockboard", msg)
                    send_gelf(f"BlockBoard: снят блок по TTL — {r['indicator']}",
                              indicator=r["indicator"], action="expire", result=msg)
                con.commit()
            # дневное окно: согласование + единственное сохранение конфигурации
            now_yekt = datetime.now(YEKT)
            if (now_yekt.hour == 4 and now_yekt.minute in DAILY_SAVE_MINUTES
                    and _daily_save_state["day"] != now_yekt.date()):
                _daily_save_state["day"] = now_yekt.date()
                daily_reconcile(con)
            con.close()
        except Exception:
            pass

# ---------------------------------------------------------------- HTTP

def row_block(r):
    return {"id": r["id"], "indicator": r["indicator"], "itype": r["itype"],
            "reason": r["reason"], "source": r["source"],
            "created": r["created"], "expires": r["expires"],
            "status": r["status"], "executor_msg": r["executor_msg"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "BlockBoard/1.0"

    def log_message(self, *a):
        pass

    # -- helpers
    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _user(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        tok = c.get("bb_session")
        if tok and tok.value in SESSIONS and SESSIONS[tok.value] > time.time():
            SESSIONS[tok.value] = time.time() + SESSION_TTL
            return BB_USER
        return None

    def _need_auth(self):
        if self._user():
            return False
        if self.path.startswith("/api/"):
            self._json({"error": "auth required"}, 401)
        else:
            self._send(302, b"", extra={"Location": "/login"})
        return True

    # -- GET
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/login":
            self._send(200, (ROOT / "login.html").read_text(encoding="utf-8"))
        elif p in ("/favicon.svg", "/logo.svg"):
            self._send(200, (ROOT / "blockboard.svg").read_bytes(), "image/svg+xml")
        elif self._need_auth():
            return
        elif p == "/":
            qs = parse_qs(urlparse(self.path).query)
            html = (ROOT / "index.html").read_text(encoding="utf-8")
            prefill = qs.get("block", [""])[0].replace("'", "").replace('"', "")[:200]
            reason = qs.get("reason", [""])[0].replace("'", "").replace('"', "")[:300]
            html = html.replace("__PREFILL_IND__", prefill).replace("__PREFILL_REASON__", reason)
            self._send(200, html)
        elif p == "/api/blocks":
            con = db()
            rows = con.execute("SELECT * FROM blocks WHERE active=1 ORDER BY created DESC").fetchall()
            _, mode = get_executor(con)
            con.close()
            self._json({"mode": mode, "blocks": [row_block(r) for r in rows]})
        elif p == "/api/history":
            con = db()
            rows = con.execute("SELECT * FROM history ORDER BY ts DESC LIMIT 200").fetchall()
            con.close()
            self._json({"history": [dict(r) for r in rows]})
        elif p == "/api/geo-stats":
            qs = parse_qs(urlparse(self.path).query)
            try:
                days = int(qs.get("days", ["30"])[0])
            except ValueError:
                days = 30
            self._json(geo_stats(days))
        elif p == "/api/settings":
            con = db()
            self._json({"mode": get_setting(con, "mode", "dryrun"),
                        "router_host": get_setting(con, "router_host", "192.168.1.1"),
                        "router_user": get_setting(con, "router_user", "admin"),
                        "router_pass_set": bool(get_setting(con, "router_pass"))})
            con.close()
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    # -- POST
    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/login":
            b = self._body()
            if b.get("user") == BB_USER and b.get("password") == BB_PASS:
                tok = secrets.token_urlsafe(24)
                SESSIONS[tok] = time.time() + SESSION_TTL
                return self._cookie(tok)
            self._json({"ok": False, "error": "неверный логин или пароль"}, 403)
            return
        if self._need_auth():
            return
        if p == "/api/logout":
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            tok = c.get("bb_session")
            if tok:
                SESSIONS.pop(tok.value, None)
            self._send(200, "{}", "application/json",
                       {"Set-Cookie": "bb_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        elif p == "/api/blocks":
            b = self._body()
            indicator = (b.get("indicator") or "").strip().lower()
            reason = (b.get("reason") or "").strip()[:500]
            source = (b.get("source") or "").strip()[:500]
            ttl = b.get("ttl_hours")
            itype = detect_type(indicator)
            if not itype:
                return self._json({"ok": False, "error": "это не IP и не домен"}, 400)
            con = db()
            dup = con.execute("SELECT id FROM blocks WHERE active=1 AND indicator=?",
                              (indicator,)).fetchone()
            if dup:
                con.close()
                return self._json({"ok": False, "error": "уже в активных блокировках"}, 409)
            expires = time.time() + float(ttl) * 3600 if ttl else None
            cur = con.execute(
                "INSERT INTO blocks(indicator,itype,reason,source,created,expires,active,status,executor_msg) "
                "VALUES(?,?,?,?,?,?,1,'pending','')",
                (indicator, itype, reason, source, time.time(), expires))
            bid = cur.lastrowid
            # save=True только при ручном действии из панели (клиент шлёт "save": true);
            # автоматические вызовы (feedpipe) не сохраняют startup-config на каждый домен
            ok, msg = apply_block(con, indicator, itype, save=bool(b.get("save")))
            con.execute("UPDATE blocks SET active=?, status=?, executor_msg=? WHERE id=?",
                        (1 if ok else 0, "active" if ok else "error", msg, bid))
            log_history(con, "block", indicator, BB_USER, f"{reason} | {msg}")
            con.commit()
            con.close()
            send_gelf(f"BlockBoard: заблокирован {indicator}", level=4,
                      indicator=indicator, itype=itype, reason=reason,
                      action="block", result=msg, ttl_hours=ttl or 0)
            self._json({"ok": ok, "id": bid, "executor_msg": msg})
        elif p.endswith("/unblock"):
            bid = int(p.split("/")[3])
            con = db()
            r = con.execute("SELECT * FROM blocks WHERE id=? AND active=1", (bid,)).fetchone()
            if not r:
                con.close()
                return self._json({"ok": False, "error": "блокировка не найдена"}, 404)
            con.execute("UPDATE blocks SET active=0, status='removing' WHERE id=?", (bid,))
            con.commit()
            ok, msg = apply_unblock(con, r["indicator"], r["itype"])
            con.execute("UPDATE blocks SET status=?, executor_msg=?, active=? WHERE id=?",
                        ("removed" if ok else "remove-error", msg, 0 if ok else 1, bid))
            log_history(con, "unblock", r["indicator"], BB_USER, msg)
            con.commit()
            con.close()
            send_gelf(f"BlockBoard: разблокирован {r['indicator']}",
                      indicator=r["indicator"], action="unblock", result=msg)
            self._json({"ok": ok, "executor_msg": msg})
        elif p.endswith("/extend"):
            bid = int(p.split("/")[3])
            hours = float(self._body().get("hours", 24))
            con = db()
            r = con.execute("SELECT * FROM blocks WHERE id=? AND active=1", (bid,)).fetchone()
            if not r:
                con.close()
                return self._json({"ok": False, "error": "не найдена"}, 404)
            base = max(time.time(), r["expires"] or time.time())
            con.execute("UPDATE blocks SET expires=? WHERE id=?", (base + hours * 3600, bid))
            log_history(con, "extend", r["indicator"], BB_USER, f"+{hours:g}ч")
            con.commit()
            con.close()
            self._json({"ok": True})
        elif p == "/api/settings":
            b = self._body()
            con = db()
            if b.get("mode") in ("dryrun", "keenetic"):
                set_setting(con, "mode", b["mode"])
            if b.get("router_host"):
                set_setting(con, "router_host", b["router_host"].strip())
            if b.get("router_user"):
                set_setting(con, "router_user", b["router_user"].strip())
            if b.get("router_pass"):
                set_setting(con, "router_pass",
                            base64.b64encode(b["router_pass"].encode()).decode())
            log_history(con, "settings", "-", BB_USER, "обновлены настройки роутера")
            con.commit()
            con.close()
            self._json({"ok": True})
        elif p == "/api/test-router":
            con = db()
            host = get_setting(con, "router_host", "192.168.1.1")
            user = get_setting(con, "router_user", "admin")
            pw_b64 = get_setting(con, "router_pass")
            con.close()
            try:
                pw = base64.b64decode(pw_b64).decode() if pw_b64 else ""
            except Exception:
                pw = ""
            if not pw:
                return self._json({"ok": False, "error": "пароль роутера не задан"}, 400)
            try:
                k = Keenetic(host, user, pw)
                info = k.show_version()
                self._json({"ok": True, "router": info})
            except KeeneticError as e:
                self._json({"ok": False, "error": str(e)})
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")


def _login_with_cookie(self, tok):
    body = b'{"ok":true}'
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Set-Cookie",
                     f"bb_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}")
    self.end_headers()
    self.wfile.write(body)


Handler._cookie = _login_with_cookie


def main():
    threading.Thread(target=sweeper, daemon=True).start()
    # при старте приводим роутер в соответствие с БД (если режим keenetic)
    try:
        con = db()
        k, mode = get_executor(con)
        if k:
            ok, msg = sync_router_acl(con, k)
            print(f"startup reconcile: {msg}")
        con.close()
    except Exception as e:
        print(f"startup reconcile failed: {e}")
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"BlockBoard слушает :{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
