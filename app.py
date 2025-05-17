from flask import Flask
from db import init_db
from auth import auth
from dashboard import dashboard
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database
init_db(app.config['DB_NAME'])

# Register blueprints
app.register_blueprint(auth)
app.register_blueprint(dashboard)

# for rule in app.url_map.iter_rules():
#     print(rule.endpoint, rule)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
