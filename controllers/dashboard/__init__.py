from flask import Blueprint

dashboard = Blueprint('dashboard', __name__, template_folder='../../views/dashboard')

from controllers.dashboard import routes
