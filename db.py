import sqlite3

# Path sa database file
db_file = "database.db"
conn = sqlite3.connect(db_file)
cur = conn.cursor()
table_name = "peripherals"
cur.execute(f"SELECT * FROM {table_name}")
rows = cur.fetchall()
columns = [description[0] for description in cur.description]
print("Columns:", columns)
for row in rows:
    row_dict = dict(zip(columns, row))
    print(row_dict)
