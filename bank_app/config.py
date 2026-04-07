# app/config.py
import os

class Config:
    # Random secret key generated at startup — secure for Flask sessions
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())