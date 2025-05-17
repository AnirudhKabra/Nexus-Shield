from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Integer, default=0)

    predictions = db.relationship('Prediction', back_populates='user')

class Prediction(db.Model):
    __tablename__ = 'predictions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hash_value = db.Column(db.Text)
    time = db.Column(db.String(100))
    hash_len = db.Column(db.Integer)
    prediction = db.Column(db.Text)

    user = db.relationship('User', back_populates='predictions')

def init_db(app):
    """Initializes the database and adds default admin user if not exists."""
    with app.app_context():
        db.create_all()

        admin_username = current_app.config['ADMIN_USERNAME']
        admin_password = current_app.config['ADMIN_PASSWORD']

        if not User.query.filter_by(username=admin_username).first():
            admin_user = User(
                username=admin_username,
                password=generate_password_hash(admin_password),
                is_admin=1
            )
            db.session.add(admin_user)
            db.session.commit()
