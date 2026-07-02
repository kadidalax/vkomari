import sqlite3
import json
import os
from config import DB_PATH

os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  color TEXT,
  sort_order INTEGER
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  group_name TEXT,
  server_address TEXT,
  client_secret TEXT,
  client_uuid TEXT,
  cpu_model TEXT,
  cpu_cores INTEGER,
  ram_total INTEGER,
  swap_total INTEGER,
  disk_total INTEGER,
  os TEXT,
  arch TEXT,
  virtualization TEXT,
  region TEXT,
  kernel_version TEXT,
  gpu_name TEXT,
  ipv4 TEXT,
  ipv6 TEXT,
  fake_ip TEXT,
  load_profile TEXT DEFAULT 'mid',
  cpu_min REAL DEFAULT 5.0,
  cpu_max REAL DEFAULT 85.0,
  mem_min REAL DEFAULT 15.0,
  mem_max REAL DEFAULT 85.0,
  swap_min REAL DEFAULT 0,
  swap_max REAL DEFAULT 5.0,
  disk_min REAL DEFAULT 30.0,
  disk_max REAL DEFAULT 80.0,
  net_min INTEGER DEFAULT 102400,
  net_max INTEGER DEFAULT 10485760,
  conn_min INTEGER DEFAULT 10,
  conn_max INTEGER DEFAULT 200,
  proc_min INTEGER DEFAULT 50,
  proc_max INTEGER DEFAULT 300,
  report_interval INTEGER DEFAULT 3,
  enabled INTEGER DEFAULT 1,
  boot_time INTEGER DEFAULT 0,
  uptime_base INTEGER DEFAULT 86400,
  traffic_reset_day INTEGER DEFAULT 1,
  sort_order INTEGER DEFAULT 0,
  komari_server TEXT,
  komari_token TEXT,
  cfmonitor_server TEXT,
  cfmonitor_token TEXT,
  report_enabled INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT,
  salt TEXT
);

CREATE TABLE IF NOT EXISTS templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  config TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

INSERT OR IGNORE INTO users (username, password, salt) VALUES (
  'admin',
  'ce751a5323c718e60248219bb18bbe95d0143e5a5a4b3101463635339a1907e9867c6715b4e8080201b8a2792388b02e6d72a53dbb9b50198e651ea479aca728',
  '3374b09b526978182746180373809613'
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('cf_diag', '[]');
"""

NODE_FIELDS = [
    'name', 'server_address', 'client_secret', 'client_uuid', 'cpu_model', 'cpu_cores',
    'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region',
    'kernel_version', 'load_profile', 'cpu_min', 'cpu_max', 'mem_min', 'mem_max',
    'swap_min', 'swap_max', 'disk_min', 'disk_max', 'net_min', 'net_max',
    'conn_min', 'conn_max', 'proc_min', 'proc_max', 'report_interval', 'enabled',
    'boot_time', 'fake_ip', 'group_name', 'gpu_name', 'ipv6', 'traffic_reset_day',
    'uptime_base', 'sort_order', 'komari_server', 'komari_token',
    'cfmonitor_server', 'cfmonitor_token', 'report_enabled'
]


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def ensure_schema():
    db = get_db()
    try:
        db.executescript(SCHEMA_SQL)
        db.commit()
    finally:
        db.close()


def normalize_node_data(data):
    out = dict(data)
    # Ensure boolean fields have defaults
    out.setdefault("enabled", 1)
    out.setdefault("report_enabled", 0)
    range_fields = [
        ('cpu_min', 'cpu_max', 100),
        ('mem_min', 'mem_max', 100),
        ('swap_min', 'swap_max', 100),
        ('disk_min', 'disk_max', 100),
        ('net_min', 'net_max', float('inf')),
        ('conn_min', 'conn_max', float('inf')),
        ('proc_min', 'proc_max', float('inf'))
    ]
    for min_key, max_key, limit in range_fields:
        try:
            mn, mx = float(out.get(min_key, 0)), float(out.get(max_key, 0))
            mn = max(0, min(limit, mn))
            mx = max(0, min(limit, mx))
            if mx < mn:
                mn, mx = mx, mn
            out[min_key] = mn
            out[max_key] = mx
        except (ValueError, TypeError):
            pass
    return out


def get_nodes():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM nodes ORDER BY sort_order ASC, id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def get_enabled_nodes():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM nodes WHERE enabled = 1 AND report_enabled = 1").fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def get_user(username):
    db = get_db()
    try:
        return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        db.close()


def update_password(username, pw_hash, salt):
    db = get_db()
    try:
        db.execute("UPDATE users SET password = ?, salt = ? WHERE username = ?", (pw_hash, salt, username))
        db.commit()
    finally:
        db.close()


def save_node(data):
    data = normalize_node_data(data)
    # Cast booleans to ints for SQLite
    data["enabled"] = 1 if data.get("enabled") else 0
    data["report_enabled"] = 1 if data.get("report_enabled") else 0
    db = get_db()
    try:
        if data.get('id'):
            set_clause = ", ".join(f"{k} = ?" for k in NODE_FIELDS)
            values = [data.get(k) for k in NODE_FIELDS] + [data['id']]
            db.execute(f"UPDATE nodes SET {set_clause} WHERE id = ?", values)
            db.commit()
            return {"status": "updated"}
        else:
            placeholders = ", ".join("?" for _ in NODE_FIELDS)
            values = [data.get(k) for k in NODE_FIELDS]
            cur = db.execute(f"INSERT INTO nodes ({', '.join(NODE_FIELDS)}) VALUES ({placeholders})", values)
            db.commit()
            return {"status": "created", "id": cur.lastrowid}
    finally:
        db.close()


def get_templates():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM templates ORDER BY id DESC").fetchall()
        return [{"id": r["id"], "name": r["name"], "config": json.loads(r["config"])} for r in rows]
    finally:
        db.close()


def get_setting(key):
    db = get_db()
    try:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None
    finally:
        db.close()


def set_setting(key, value):
    db = get_db()
    try:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))
        db.commit()
    finally:
        db.close()
