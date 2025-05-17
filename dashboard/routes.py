from flask import render_template, request, jsonify, session, redirect, url_for, current_app
import sqlite3
import joblib
from . import dashboard

@dashboard.route('/<username>/scan')
def scan(username):
    """Main dashboard page after login."""
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    
    if session['username'] != username:
        return "Unauthorized access", 403

    return render_template('index.html', username=session['username'], is_admin=session.get('is_admin', 0))


@dashboard.route('/predict', methods=['POST'])
def predict():
    """API endpoint to predict whether a file is malware based on hash length and time."""
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    model = joblib.load(current_app.config["MODEL_PATH"])

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
        conn = sqlite3.connect(current_app.config["DB_NAME"])
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

@dashboard.route('/<username>/history')
def user_history(username):
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    if session['username'] != username:
        return "Unauthorized access", 403

    conn = sqlite3.connect(current_app.config["DB_NAME"])
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        return "User not found", 404

    user_id = user[0]
    c.execute("SELECT hash_value, time, hash_len, prediction FROM predictions WHERE user_id = ?", (user_id,))
    history = c.fetchall()
    conn.close()

    return render_template('history.html', history=history, username=username)



@dashboard.route('/<username>/all', methods=['GET'])
def get_all_predictions(username):
    """API endpoint to retrieve all predictions (admin only)."""

    if 'username' not in session or session['username'] != username:
        return "Unauthorized access", 403

    if not session.get('is_admin'):
        return "Access denied: Admins only", 403

    conn = sqlite3.connect(current_app.config["DB_NAME"])
    c = conn.cursor()
    c.execute('''
    SELECT p.id, u.username, p.hash_value, p.time, p.hash_len, p.prediction
    FROM predictions p
    JOIN users u ON p.user_id = u.id
    ''')

    rows = c.fetchall()
    conn.close()
    return jsonify(rows)

@dashboard.route('/<username>/view', methods=['GET'])
def view_predictions_page(username):
    """Admin-only page to view all predictions."""
    if not session.get('is_admin'):
        return "Access denied: Admins only", 403

    return render_template('all_predictions.html', username=username)

@dashboard.route('/<username>/all_users')
def all_users(username):
    """Admin-only page to view all registered users."""
    if 'username' not in session or session['username'] != username:
        return "Unauthorized access", 403

    if not session.get('is_admin'):
        return "Access denied: Admins only", 403

    conn = sqlite3.connect(current_app.config["DB_NAME"])
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users")
    users = c.fetchall()
    conn.close()

    return render_template('all_users.html', users=users, username=username)

