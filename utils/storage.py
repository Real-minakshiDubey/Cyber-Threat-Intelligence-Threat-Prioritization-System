import sqlite3
import os
from datetime import datetime

os.makedirs("data", exist_ok=True)
DB_FILE = "data/sentinel.db"

import json

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
    
    # Ensure complex data columns exist for new UI filters/analytics securely.
    new_cols = [
        ("malicious", "INTEGER DEFAULT 0"),
        ("suspicious", "INTEGER DEFAULT 0"),
        ("abuse_score", "INTEGER DEFAULT 0"),
        ("open_ports", "TEXT DEFAULT '[]'")
    ]
    for col_name, col_type in new_cols:
        try:
            c.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass # Column already exists
            
    conn.commit()
    conn.close()

init_db()

def save_scan(data):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (timestamp, ip, score, level, malicious, suspicious, abuse_score, open_ports)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(), 
        data.get("ip"), 
        data.get("score"), 
        data.get("level"),
        data.get("malicious", 0),
        data.get("suspicious", 0),
        data.get("abuse_score", 0),
        json.dumps(data.get("open_ports", []))
    ))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        r_dict = dict(row)
        # Rehydrate json array safely
        if r_dict.get("open_ports") and isinstance(r_dict["open_ports"], str):
            try:
                r_dict["open_ports"] = json.loads(r_dict["open_ports"])
            except:
                r_dict["open_ports"] = []
        else:
            r_dict["open_ports"] = []
        results.append(r_dict)
    return results

def clear_scans():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()