from flask import Blueprint

auth = Blueprint('auth', __name__, template_folder='../../views/auth')

from controllers.auth import routes