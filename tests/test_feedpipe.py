import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import feedpipe


def _mk_db(tmp_path, rows):
    db = tmp_path / "trafficlens.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE iocs(type TEXT, value TEXT, source TEXT, info TEXT,"
                " tags TEXT, confidence INTEGER, port INTEGER, first_seen REAL, last_seen REAL)")
    now = time.time()
    con.executemany("INSERT INTO iocs VALUES(?,?,?,?,?,?,?,?,?)",
                    [(*r, now, now) for r in rows])
    con.commit()
    con.close()
    return db


def test_public_ip():
    assert feedpipe.public_ip("8.8.8.8") == "8.8.8.8"
    assert feedpipe.public_ip("192.168.1.1") is None
    assert feedpipe.public_ip("10.0.0.5") is None
    assert feedpipe.public_ip("127.0.0.1") is None
    assert feedpipe.public_ip("224.0.0.1") is None
    assert feedpipe.public_ip("не-ip") is None


def test_valid_domain():
    assert feedpipe.valid_domain("evil-c2.example.com")
    assert not feedpipe.valid_domain("router.local")
    assert not feedpipe.valid_domain("host.internal")
    assert not feedpipe.valid_domain("nodot")
    assert not feedpipe.valid_domain("bad domain.com")


def test_load_iocs_filters(tmp_path, monkeypatch):
    now = time.time()
    db = _mk_db(tmp_path, [
        ("ip", "8.8.8.8", "feodo", "botnet C2", "", 90, None),        # берём
        ("ip", "192.168.1.1", "custom", "внутренний", "", 100, None), # приватный — нет
        ("ip", "1.2.3.4", "urlhaus", "malware", "", 75, None),        # conf < 80 — нет
        ("domain", "c2.evil.com", "misp", "C2", "", 80, None),        # берём
        ("domain", "printer.local", "custom", "", "", 100, None),     # .local — нет
        ("ja3", "334da95730484a993c6063e36bc90a47", "sslbl", "", "", 80, None),  # ja3 — нет
        ("url", "http://x.evil.com/a", "urlhaus", "", "", 90, None),  # url — нет
    ])
    # старый IOC — не берём
    con = sqlite3.connect(db)
    con.execute("INSERT INTO iocs VALUES('ip','9.9.9.9','feodo','старый','',90,NULL,?,?)",
                (now - 40 * 86400, now - 40 * 86400))
    con.commit(); con.close()
    monkeypatch.setattr(feedpipe, "TL_DB", db)
    out = feedpipe.load_iocs()
    inds = {i["indicator"] for i in out}
    assert inds == {"8.8.8.8", "c2.evil.com"}
    # сортировка по confidence убыванию
    assert out[0]["confidence"] >= out[-1]["confidence"]


def test_load_iocs_missing_db(tmp_path, monkeypatch):
    monkeypatch.setattr(feedpipe, "TL_DB", tmp_path / "none.db")
    try:
        feedpipe.load_iocs()
        assert False, "ждали SystemExit"
    except SystemExit:
        pass
