"""Entry point – run: python run.py"""
import os
from dotenv import load_dotenv

# Load .env relative to this file's directory
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(_env_path)

from app import create_app
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

app = create_app()

if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, use_reloader=FLASK_DEBUG)
