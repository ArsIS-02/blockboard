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
import base64, gzip, hashlib, ipaddress, json, os, re, secrets, socket, sqlite3
import ssl, threading, time, urllib.request, urllib.error
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

    def __init__(self, host, user, password, timeout=10):
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
        md5 = hashlib.md5((self.user + realm + self.password).encode()).hexdigest()
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
        return json.loads(body or b"[]")

    def show_version(self):
        r = self.rci({"show": {"version": {}}})
        v = r[0] if r else {}
        return f"{v.get('model', '?')} · NDMS {v.get('release', v.get('version', '?'))}"

    def block_ip(self, ip):
        self.rci({"ip": {"route": {"host": ip, "mask": "255.255.255.255",
                                    "reject": True, "description": "blockboard"}}},
                  {"system": {"configuration": {"save": True}}})

    def unblock_ip(self, ip):
        self.rci({"no": {"ip": {"route": {"host": ip, "mask": "255.255.255.255",
                                           "reject": True}}}},
                  {"system": {"configuration": {"save": True}}})

    def block_domain(self, domain):
        # статическая DNS-запись: роутер отвечает 0.0.0.0 всем клиентам сети
        self.rci({"ip": {"host": {"name": domain, "address": "0.0.0.0"}}},
                  {"system": {"configuration": {"save": True}}})

    def unblock_domain(self, domain):
        self.rci({"no": {"ip": {"host": {"name": domain}}}},
                  {"system": {"configuration": {"save": True}}})


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


def apply_block(con, indicator, itype):
    k, mode = get_executor(con)
    if not k:
        return True, "dry-run: действие записано, роутер не подключён"
    try:
        if itype == "ip":
            k.block_ip(indicator)
        else:
            k.block_domain(indicator)
        return True, f"keenetic: {indicator} заблокирован"
    except KeeneticError as e:
        return False, f"keenetic: ошибка — {e}"


def apply_unblock(con, indicator, itype):
    k, mode = get_executor(con)
    if not k:
        return True, "dry-run: действие записано, роутер не подключён"
    try:
        if itype == "ip":
            k.unblock_ip(indicator)
        else:
            k.unblock_domain(indicator)
        return True, f"keenetic: {indicator} разблокирован"
    except KeeneticError as e:
        return False, f"keenetic: ошибка — {e}"

# ---------------------------------------------------------------- фон: снятие по TTL

def sweeper():
    while True:
        time.sleep(60)
        try:
            con = db()
            now = time.time()
            rows = con.execute("SELECT * FROM blocks WHERE active=1 AND expires IS NOT NULL "
                               "AND expires<?", (now,)).fetchall()
            for r in rows:
                ok, msg = apply_unblock(con, r["indicator"], r["itype"])
                con.execute("UPDATE blocks SET active=0, status=?, executor_msg=? WHERE id=?",
                            ("expired" if ok else "expire-error", msg, r["id"]))
                log_history(con, "expire", r["indicator"], "blockboard", msg)
                send_gelf(f"BlockBoard: снят блок по TTL — {r['indicator']}",
                          indicator=r["indicator"], action="expire", result=msg)
            con.commit()
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
            ok, msg = apply_block(con, indicator, itype)
            cur = con.execute(
                "INSERT INTO blocks(indicator,itype,reason,source,created,expires,active,status,executor_msg) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (indicator, itype, reason, source, time.time(), expires,
                 1 if ok else 0, "active" if ok else "error", msg))
            log_history(con, "block", indicator, BB_USER, f"{reason} | {msg}")
            con.commit()
            bid = cur.lastrowid
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
            ok, msg = apply_unblock(con, r["indicator"], r["itype"])
            con.execute("UPDATE blocks SET active=0, status=?, executor_msg=? WHERE id=?",
                        ("removed" if ok else "remove-error", msg, bid))
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
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"BlockBoard слушает :{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
