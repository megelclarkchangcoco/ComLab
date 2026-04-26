import sqlite3

DB_FILE = "database.db"

try:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("DELETE FROM active_sessions")
    conn.commit()

    print("Successfully cleared all active sessions.")
    print("All PCs should now show as Available until a student/professor logs in again.")

except Exception as e:
    print("Error clearing active sessions:")
    print(e)

finally:
    try:
        conn.close()
    except:
        pass