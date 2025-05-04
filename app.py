from flask import Flask, request, jsonify, render_template
import joblib
import sqlite3
import os

app = Flask(__name__)

# Load the ML model
model = joblib.load("malware_model.pkl")

DB_NAME = 'malware_predictions.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT,
            time TEXT,
            hash_len INTEGER,
            prediction TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if not all(key in data for key in ['hash', 'time']):
        return jsonify({"error": "Missing required fields (hash, time)"}), 400

    hash_value = data['hash']
    time = data['time']
    hash_len = len(hash_value)

    try:
        prediction = model.predict([[hash_len, time]])[0]
        label = "Malware" if prediction == 1 else "Not Malware"
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO predictions (hash_value, time, hash_len, prediction) VALUES (?, ?, ?, ?)",
                  (hash_value, time, hash_len, label))
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"error": f"Database error: {e}"}), 500

    return jsonify({"prediction": label})

@app.route('/all', methods=['GET'])
def get_all_predictions():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM predictions")
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)

@app.route('/view', methods=['GET'])
def view_predictions_page():
    return render_template('all_predictions.html')

if __name__ == '__main__':
    app.run(debug=True)
