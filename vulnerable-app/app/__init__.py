"""Tiny Flask application factory for the vulnerable target."""

from flask import Flask

from .views import bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
