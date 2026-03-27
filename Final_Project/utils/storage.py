import sqlite3
import os
from datetime import datetime

os.makedirs("data", exist_ok=True)
DB_FILE = "data/sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            score REAL,
            level TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def save_scan(data):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (timestamp, ip, score, level)
        VALUES (?, ?, ?, ?)
    ''', (datetime.now().isoformat(), data.get("ip"), data.get("score"), data.get("level")))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_scans():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()