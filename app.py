from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key' 

# Constants
DB_NAME = 'malware_predictions.db'
MODEL_PATH = 'malware_model.pkl'

# Load the machine learning model
model = joblib.load(MODEL_PATH)

# ----------------------------- #
#       Database Setup          #
# ----------------------------- #
def init_db():
    """Initializes the SQLite database and required tables."""
    conn = sqlite3.connect(DB_NAME)
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
    # Insert default admin user if not already present
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                ('admin', hashed_admin_password, 1))

    conn.commit()
    conn.close()

# Initialize database on app start
init_db()


# ----------------------------- #
#        Route Handlers         #
# ----------------------------- #

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  
            session['username'] = username
            session['is_admin'] = user[3]
            return redirect(url_for('dashboard'))
        return "Invalid credentials"

    return render_template('login.html')



@app.route('/logout')
def logout():
    """Logout route to clear session."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        conn.close()
        return redirect(url_for('login'))

    return render_template('signup.html')



@app.route('/scan')
def dashboard():
    """Main dashboard page after login."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'], is_admin=session.get('is_admin', 0))

@app.route('/predict', methods=['POST'])
def predict():
    """API endpoint to predict whether a file is malware based on hash length and time."""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    if not all(key in data for key in ['hash', 'time']):
        return jsonify({"error": "Missing required fields (hash, time)"}), 400

    hash_value = data['hash']
    time = data['time']
    hash_len = len(hash_value)

    try:
        prediction = model.predict([[hash_len, time]])[0]
        label = "Malware" if prediction == 1 else "Clean"
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Fetch user_id from session username
        c.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
        user = c.fetchone()
        user_id = user[0] if user else None

        if not user_id:
            return jsonify({"error": "User not found"}), 400

        # Save prediction with user_id
        c.execute(
            "INSERT INTO predictions (user_id, hash_value, time, hash_len, prediction) VALUES (?, ?, ?, ?, ?)",
            (user_id, hash_value, time, hash_len, label)
        )

        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"error": f"Database error: {e}"}), 500

    return jsonify({"prediction": label})

@app.route('/history')
def user_history():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
    user = c.fetchone()
    if not user:
        return "User not found", 404

    user_id = user[0]
    c.execute("SELECT hash_value, time, hash_len, prediction FROM predictions WHERE user_id = ?", (user_id,))
    history = c.fetchall()
    conn.close()

    return render_template('history.html', history=history, username=session['username'])

@app.route('/all', methods=['GET'])
def get_all_predictions():
    """API endpoint to retrieve all predictions from the database."""

    if not session.get('is_admin'):
        return "Access denied: Admins only", 403
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
    SELECT p.id, u.username, p.hash_value, p.time, p.hash_len, p.prediction
    FROM predictions p
    JOIN users u ON p.user_id = u.id
    ''')

    rows = c.fetchall()
    conn.close()
    return jsonify(rows)


@app.route('/view', methods=['GET'])
def view_predictions_page():
    """Admin-only page to view all predictions."""
    if not session.get('is_admin'):
        return "Access denied: Admins only", 403
    return render_template('all_predictions.html')


@app.route('/all_users')
def all_users():
    """Admin-only page to view all registered users."""
    if not session.get('is_admin'):
        return "Access denied: Admins only", 403

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users")
    users = c.fetchall()
    conn.close()

    return render_template('all_users.html', users=users)


# ----------------------------- #
#       App Entry Point         #
# ----------------------------- #
if __name__ == '__main__':
    app.run(host='0.0.0.0') # For production use
    # app.run(debug=True) # For development purposes only
