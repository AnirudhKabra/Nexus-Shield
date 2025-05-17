from flask import Flask
from db import db, init_db
from auth import auth
from dashboard import dashboard
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Initialize SQLAlchemy with the Flask app
db.init_app(app)

# Initialize the database and default admin user
init_db(app)

# Register blueprints
app.register_blueprint(auth)
app.register_blueprint(dashboard)

# Optional: print all routes
# for rule in app.url_map.iter_rules():
#     print(rule.endpoint, rule)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
