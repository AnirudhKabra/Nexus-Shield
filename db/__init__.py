import sqlite3
from werkzeug.security import generate_password_hash

def init_db(db_name):
    """Initializes the SQLite database and required tables."""
    conn = sqlite3.connect(db_name)
    c = conn.cursor()

    # Table to store predictions
    c.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            hash_value TEXT,
            time TEXT,
            hash_len INTEGER,
            prediction TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Table to store user credentials
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')

    # Insert default admin user if not already present
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                  ('admin', hashed_admin_password, 1))

    conn.commit()
    conn.close()
