import sqlite3

DB_PATH = "database.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS detected_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_id INTEGER NOT NULL,
    pc_tag TEXT NOT NULL,
    unique_id TEXT NOT NULL,
    name TEXT,
    device_type TEXT,
    vendor TEXT,
    product TEXT,
    serial_number TEXT,
    status TEXT DEFAULT 'connected',
    last_seen TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(lab_id, pc_tag, unique_id)
)
""")

conn.commit()
conn.close()

print("detected_devices table created successfully.")