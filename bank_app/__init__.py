# app/__init__.py
from flask import Flask
from .config import Config
from . import models
from .routes import bp as main_bp


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(Config)

    # Initialize in-memory users
    models.init_users()

    # Register blueprint
    app.register_blueprint(main_bp)

    return app