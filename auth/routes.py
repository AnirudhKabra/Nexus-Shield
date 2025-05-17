from flask import render_template, request, redirect, url_for, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from . import auth

@auth.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(current_app.config["DB_NAME"])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  
            session['username'] = username
            session['is_admin'] = user[3]
            return redirect(url_for('dashboard.scan', username=username))
        return "Invalid credentials"

    return render_template('login.html')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect(current_app.config["DB_NAME"])
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        conn.close()
        return redirect(url_for('auth.login'))

    return render_template('signup.html')

@auth.route('/logout')
def logout():
    """Logout route to clear session."""
    session.clear()
    return redirect(url_for('auth.login'))
