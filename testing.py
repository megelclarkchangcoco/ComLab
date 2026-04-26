import sqlite3
from datetime import datetime

DB_FILE = "database.db"

with sqlite3.connect(DB_FILE) as conn:
    cur = conn.cursor()
    cur.execute("""
    DELETE FROM peripheral_alerts 
     """)

    rows = cur.fetchall()
    for r in rows:
        print(r)
