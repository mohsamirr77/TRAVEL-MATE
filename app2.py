from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import config

from models import db, User, Admin, RidePost, RideRequest, Feedback, Notification, ChatMessage, Chat, Message

app = Flask(__name__)
app.config.from_object(config)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ✅ Initialize Flask-Migrate
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(debug=True)
