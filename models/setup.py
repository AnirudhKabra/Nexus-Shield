from flask import current_app
from werkzeug.security import generate_password_hash
from models import db, User

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
