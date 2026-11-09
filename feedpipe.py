#!/usr/bin/env python3
"""FeedPipe — конвейер «фиды IOC → BlockBoard».

Читает базу IOC TrafficLens (SQLite), отбирает индикаторы с высоким доверием
и блокирует их через API BlockBoard. Дедупликация — на стороне BlockBoard
(409 «уже в активных»), поэтому скрипт идемпотентен и безопасен для запуска
по таймеру.

ENV:
  FP_TL_DB        — путь к trafficlens.db (~/trafficlens/data/trafficlens.db)
  FP_BB_URL       — BlockBoard API (http://127.0.0.1:8098)
  FP_BB_USER/PASS — учётка BlockBoard (admin/admin)
  FP_MIN_CONF     — минимальный confidence (80)
  FP_TTL_HOURS    — TTL блокировки, часов (168 = 7 суток)
  FP_MAX_AGE_DAYS — не брать IOC, не обновлявшиеся дольше N дней (30)
  FP_MAX_PER_RUN  — потолок новых блокировок за прогон (50)
  FP_DRY          — 1: только показать, что было бы заблокировано
"""
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.request
from http import cookies
from pathlib import Path

TL_DB = Path(os.environ.get("FP_TL_DB", "~/trafficlens/data/trafficlens.db")).expanduser()
BB_URL = os.environ.get("FP_BB_URL", "http://127.0.0.1:8098").rstrip("/")
BB_USER = os.environ.get("FP_BB_USER", "admin")
BB_PASS = os.environ.get("FP_BB_PASS", "admin")
MIN_CONF = int(os.environ.get("FP_MIN_CONF", "80"))
TTL_HOURS = float(os.environ.get("FP_TTL_HOURS", "168"))
MAX_AGE = int(os.environ.get("FP_MAX_AGE_DAYS", "30")) * 86400
MAX_PER_RUN = int(os.environ.get("FP_MAX_PER_RUN", "50"))
DRY = os.environ.get("FP_DRY", "") == "1"

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SKIP_TLD = (".local", ".internal", ".lan", ".home", ".corp", ".test")


def public_ip(value):
    """IP строкой, если он публичный и глобально маршрутизируемый, иначе None."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_global and not (ip.is_multicast or ip.is_loopback
                             or ip.is_link_local or ip.is_reserved
                             or ip.is_unspecified):
        return str(ip)
    return None


def valid_domain(value):
    if any(value.endswith(t) for t in SKIP_TLD):
        return False
    return bool(DOMAIN_RE.match(value))


def load_iocs():
    """IOC из TrafficLens: ip/domain, conf >= MIN_CONF, свежие."""
    if not TL_DB.exists():
        raise SystemExit(f"feedpipe: нет базы TrafficLens: {TL_DB}")
    con = sqlite3.connect(TL_DB)
    con.row_factory = sqlite3.Row
    cutoff = time.time() - MAX_AGE
    rows = con.execute(
        "SELECT type, value, source, info, confidence, last_seen FROM iocs "
        "WHERE type IN ('ip','domain') AND confidence >= ? AND last_seen >= ?",
        (MIN_CONF, cutoff)).fetchall()
    con.close()
    out = []
    for r in rows:
        v = (r["value"] or "").strip().lower()
        if r["type"] == "ip":
            v = public_ip(v)
            if not v:
                continue
        elif not valid_domain(v):
            continue
        if "offline" in (r["info"] or "").lower():
            continue  # мёртвые C2 из Feodo — не тратим место в ACL
        out.append({"indicator": v, "itype": r["type"], "source": r["source"],
                    "info": r["info"] or "", "confidence": r["confidence"]})
    out.sort(key=lambda x: -x["confidence"])
    return out


class BB:
    def __init__(self):
        self.opener = urllib.request.build_opener()
        self.token = ""

    def _req(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BB_URL + path, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if data else "GET")
        if self.token:
            req.add_header("Cookie", f"bb_session={self.token}")
        try:
            with self.opener.open(req, timeout=30) as r:
                setc = r.headers.get("Set-Cookie", "")
                m = cookies.SimpleCookie(setc)
                if "bb_session" in m:
                    self.token = m["bb_session"].value
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}

    def login(self):
        st, r = self._req("/api/login", {"user": BB_USER, "password": BB_PASS})
        if st != 200:
            raise SystemExit(f"feedpipe: вход в BlockBoard не удался (HTTP {st})")

    def active(self):
        st, r = self._req("/api/blocks")
        return {b["indicator"] for b in r.get("blocks", [])} if st == 200 else set()

    def block(self, ind, reason, source):
        return self._req("/api/blocks", {"indicator": ind, "reason": reason,
                                         "source": source, "ttl_hours": TTL_HOURS})


def main():
    iocs = load_iocs()
    print(f"feedpipe: кандидатов из TrafficLens (conf>={MIN_CONF}): {len(iocs)}")
    if DRY:
        for i in iocs[:MAX_PER_RUN]:
            print(f"  [dry] {i['indicator']} ({i['itype']}, conf {i['confidence']}, {i['source']}) — {i['info'][:60]}")
        return
    bb = BB()
    bb.login()
    already = bb.active()
    added = skipped = errors = 0
    for i in iocs:
        if added >= MAX_PER_RUN:
            print(f"feedpipe: достигнут потолок {MAX_PER_RUN} за прогон")
            break
        if i["indicator"] in already:
            skipped += 1
            continue
        st, r = bb.block(i["indicator"],
                         f"{i['info'][:180]}" or f"IOC {i['source']}",
                         f"feedpipe:{i['source']}")
        if st == 200 and r.get("ok"):
            added += 1
            print(f"  + {i['indicator']} (conf {i['confidence']}, {i['source']})")
        elif st == 409:
            skipped += 1
        else:
            errors += 1
            print(f"  ! {i['indicator']}: HTTP {st} {r.get('error', '')}")
    print(f"feedpipe: добавлено {added}, уже было {skipped}, ошибок {errors}")


if __name__ == "__main__":
    main()
