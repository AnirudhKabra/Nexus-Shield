import sqlite3

conn = sqlite3.connect('instance/prod.db')
cursor = conn.cursor()

# List tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables:", tables)

print()

# Fetch all rows from users table
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()
for row in rows:
    print(row)

print()

cursor.execute("SELECT * FROM predictions")
rows = cursor.fetchall()
for row in rows:
    print(row)


conn.close()