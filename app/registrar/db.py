"""SQLite storage. The database is the source of truth; DNS is derived from it."""
import datetime
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    pw_hash      TEXT NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);

-- status: pending | approved | rejected | released (owner gave it up) | revoked (admin removed it)
CREATE TABLE IF NOT EXISTS domains (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    tld        TEXT NOT NULL,
    owner_id   INTEGER NOT NULL REFERENCES users(id),
    ip         TEXT NOT NULL,
    purpose    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending',
    admin_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT
);

-- A name can only be held once. Enforced by the database so concurrent requests cannot break it.
-- (How MANY names one student may hold is a setting, MAX_DOMAINS_PER_STUDENT, checked in the app.)
CREATE UNIQUE INDEX IF NOT EXISTS domains_active_name
    ON domains(name, tld) WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
"""

ACTIVE = ("pending", "approved")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect(path, query_only=False):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if query_only:
        conn.execute("PRAGMA query_only=ON")
    return conn


def init_db(path):
    conn = connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.execute("DROP INDEX IF EXISTS domains_active_owner_tld")   # older versions: one name per TLD
    conn.commit()
    conn.close()


def log_event(conn, actor, action, detail=""):
    conn.execute(
        "INSERT INTO events (ts, actor, action, detail) VALUES (?,?,?,?)",
        (utcnow(), actor, action, detail),
    )
