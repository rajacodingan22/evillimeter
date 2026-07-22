import sqlite3
import os
import threading
import time


class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "..", "evillimiter.db"
            )
        self.db_path = os.path.abspath(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    manufacturer TEXT DEFAULT '',
                    device_type TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    UNIQUE(mac)
                );

                CREATE TABLE IF NOT EXISTS limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    rate TEXT DEFAULT '',
                    direction TEXT DEFAULT 'both',
                    is_blocked INTEGER DEFAULT 0,
                    quota_bytes INTEGER DEFAULT 0,
                    quota_used INTEGER DEFAULT 0,
                    quota_reset_at REAL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(mac) REFERENCES hosts(mac)
                );

                CREATE TABLE IF NOT EXISTS bandwidth_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    uploaded INTEGER DEFAULT 0,
                    downloaded INTEGER DEFAULT 0,
                    logged_at REAL NOT NULL,
                    FOREIGN KEY(mac) REFERENCES hosts(mac)
                );

                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT DEFAULT '',
                    action TEXT NOT NULL,
                    detail TEXT DEFAULT '',
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            conn.commit()

    def upsert_host(self, ip, mac, name="", manufacturer="", device_type=""):
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO hosts (ip, mac, name, manufacturer, device_type, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        ip=excluded.ip,
                        name=CASE WHEN excluded.name != '' THEN excluded.name ELSE hosts.name END,
                        manufacturer=CASE WHEN excluded.manufacturer != '' THEN excluded.manufacturer ELSE hosts.manufacturer END,
                        device_type=CASE WHEN excluded.device_type != '' THEN excluded.device_type ELSE hosts.device_type END,
                        last_seen=excluded.last_seen
                """,
                    (ip, mac, name, manufacturer, device_type, now, now),
                )

    def get_all_hosts(self):
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
                return [dict(r) for r in rows]

    def get_host_by_mac(self, mac):
        with self._lock:
            with self._connect() as conn:
                r = conn.execute("SELECT * FROM hosts WHERE mac=?", (mac,)).fetchone()
                return dict(r) if r else None

    def set_limit(self, mac, rate="", direction="both", is_blocked=0, quota_bytes=0):
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT id FROM limits WHERE mac=?", (mac,)
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE limits SET rate=?, direction=?, is_blocked=?, quota_bytes=?, updated_at=?
                        WHERE mac=?
                    """,
                        (rate, direction, is_blocked, quota_bytes, now, mac),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO limits (mac, rate, direction, is_blocked, quota_bytes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (mac, rate, direction, is_blocked, quota_bytes, now, now),
                    )

    def get_limit(self, mac):
        with self._lock:
            with self._connect() as conn:
                r = conn.execute("SELECT * FROM limits WHERE mac=?", (mac,)).fetchone()
                return dict(r) if r else None

    def update_quota_used(self, mac, bytes_used):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO limits (mac, quota_used, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        quota_used=quota_used+?, updated_at=?
                """,
                    (
                        mac,
                        bytes_used,
                        time.time(),
                        time.time(),
                        bytes_used,
                        time.time(),
                    ),
                )

    def log_bandwidth(self, mac, uploaded, downloaded):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO bandwidth_log (mac, uploaded, downloaded, logged_at)
                    VALUES (?, ?, ?, ?)
                """,
                    (mac, uploaded, downloaded, time.time()),
                )

    def get_bandwidth_history(self, mac=None, limit=100):
        with self._lock:
            with self._connect() as conn:
                if mac:
                    rows = conn.execute(
                        """
                        SELECT * FROM bandwidth_log WHERE mac=? ORDER BY logged_at DESC LIMIT ?
                    """,
                        (mac, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM bandwidth_log ORDER BY logged_at DESC LIMIT ?
                    """,
                        (limit,),
                    ).fetchall()
                return [dict(r) for r in rows]

    def log_activity(self, action, detail="", mac=""):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO activity_log (mac, action, detail, timestamp)
                    VALUES (?, ?, ?, ?)
                """,
                    (mac, action, detail, time.time()),
                )

    def get_activity_log(self, limit=50):
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?
                """,
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]

    def get_setting(self, key, default=None):
        with self._lock:
            with self._connect() as conn:
                r = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (key,)
                ).fetchone()
                return r["value"] if r else default

    def set_setting(self, key, value):
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                    (key, value),
                )
                conn.commit()
