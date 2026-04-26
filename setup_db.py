import sqlite3
DB_FILE = "database.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row

        # Admin login table
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS admins
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         username
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         password
                         TEXT
                         NOT
                         NULL
                     )
                     """)

        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("""
                        CREATE TABLE IF NOT EXISTS labs
                        (
                            id
                            INTEGER
                            PRIMARY
                            KEY
                            AUTOINCREMENT,
                            name
                            TEXT
                            NOT
                            NULL
                            UNIQUE
                        )
                        """)
            conn.commit()

            # Optional auto seed if empty
            cur.execute("SELECT COUNT(*) FROM labs")
            if cur.fetchone()[0] == 0:
                cur.executemany("INSERT INTO labs (name) VALUES (?)", [
                    ("ComLab 1",),
                    ("ComLab 2",),
                    ("ComLab 3",)
                ])
                conn.commit()
        # Student login table
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS student_users
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         username
                         TEXT
                         UNIQUE
                         NOT
                         NULL,
                         password
                         TEXT
                         NOT
                         NULL
                     )
                     """)

        # Devices table
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS devices
                     (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         tag TEXT,
                         location TEXT,
                         hostname TEXT,
                         ip_addres TEXT,
                         created_a TEXT,
                         assigned_student TEXT,
                         used INTEGER DEFAULT 0,
                         comlab_id INTEGER DEFAULT 0,
                         last_assigned_student TEXT
                     )
                     """)

        # Students master list (include plaintext password and status for admin view)
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS students
                     (
                         id
                         TEXT
                         PRIMARY
                         KEY,
                         name
                         TEXT,
                         grade_section
                         TEXT,
                         remarks
                         TEXT,
                         password
                         TEXT
                         DEFAULT
                         '',
                         status
                         TEXT
                         DEFAULT
                         '',
                         deleted
                         INTEGER
                         DEFAULT
                         0
                     )
                     """)

        # Active sessions table
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS active_sessions
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         pc_tag
                         TEXT
                         UNIQUE,
                         student_id
                         TEXT,
                         student_name
                         TEXT,
                         login_time
                         TEXT
                     )
                     """)

        # Device tokens table
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS device_tokens
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         token
                         TEXT
                         UNIQUE,
                         created_at
                         TEXT,
                         used
                         INTEGER
                         DEFAULT
                         0
                     )
                     """)

        # Anomalies table (with cleared flag for soft-delete)
        conn.execute("""
                     CREATE TABLE IF NOT EXISTS anomalies
                     (
                         id
                         INTEGER
                         PRIMARY
                         KEY
                         AUTOINCREMENT,
                         device_id
                         INTEGER,
                         student_id
                         TEXT,
                         pc_tag
                         TEXT,
                         anomaly_type
                         TEXT,
                         details
                         TEXT,
                         detected_at
                         TEXT,
                         detected_by
                         TEXT,
                         device_unit
                         TEXT,
                         student_name
                         TEXT,
                         last_student_name
                         TEXT,
                         cleared
                         INTEGER
                         DEFAULT
                         0,
                         FOREIGN
                         KEY
                     (
                         device_id
                     ) REFERENCES devices
                     (
                         id
                     )
                         )
                     """)
        conn.execute("""
        CREATE TABLE IF
        NOT EXISTS peripheral_history(id
        INTEGER
        PRIMARY
        KEY
        AUTOINCREMENT,
        peripheral_id
        INTEGER
        NOT
        NULL,
        pc_tag
        TEXT
        NOT
        NULL,
        name
        TEXT,
        brand
        TEXT,
        serial_number
        TEXT,
        status
        TEXT,
        action
        TEXT, -- "Added", "Edited", "Deleted", "Replaced"
        performed_by
        TEXT, -- optional: user / admin
        timestamp
        DATETIME
        DEFAULT
        CURRENT_TIMESTAMP,
        FOREIGN
        KEY(peripheral_id)
        REFERENCES
        peripherals(id)
        );
        """)

        conn.commit()
    conn.close()
    print("Database initialized.")

init_db()