from flask import render_template, request, jsonify, session, redirect, url_for, current_app
import joblib
from sqlalchemy.exc import SQLAlchemyError
from . import dashboard
from db import User, Prediction, db 

@dashboard.route('/<username>/scan')
def scan(username):
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    return render_template('index.html', username=session['username'], is_admin=session.get('is_admin', 0))


@dashboard.route('/predict', methods=['POST'])
def predict():
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
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({"error": "User not found"}), 400

        new_prediction = Prediction(
            user_id=user.id,
            hash_value=hash_value,
            time=time,
            hash_len=hash_len,
            prediction=label
        )
        db.session.add(new_prediction)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify({"prediction": label})


@dashboard.route('/<username>/history')
def user_history(username):
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404

    history = Prediction.query.filter_by(user_id=user.id).all()

    # for item in history:
    #     print(f"ID: {item.id}, Result: {item.prediction}")


    return render_template('history.html', history=history, username=username)


@dashboard.route('/<username>/all', methods=['GET'])
def get_all_predictions(username):
    if 'username' not in session or session['username'] != username:
        return "Unauthorized access", 403

    # Join predictions with users to get username along with prediction data
    rows = db.session.query(
        Prediction.id,
        User.username,
        Prediction.hash_value,
        Prediction.time,
        Prediction.hash_len,
        Prediction.prediction
    ).join(User, Prediction.user_id == User.id).all()

    # Convert rows to list of dicts for JSON response
    results = []
    for r in rows:
        results.append({
            'id': r.id,
            'username': r.username,
            'hash_value': r.hash_value,
            'time': r.time,
            'hash_len': r.hash_len,
            'prediction': r.prediction
        })

    # print(results)

    return jsonify(results)


@dashboard.route('/<username>/view', methods=['GET'])
def view_predictions_page(username):
    if not session.get('is_admin'):
        return "Access denied: Admins only", 403

    return render_template('all_predictions.html', username=username)


@dashboard.route('/<username>/all_users')
def all_users(username):
    if 'username' not in session or session['username'] != username:
        return "Unauthorized access", 403

    users = User.query.with_entities(User.id, User.username, User.is_admin).all()

    return render_template('all_users.html', users=users, username=username)
