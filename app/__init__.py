from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
    db_path = os.path.join(app.instance_path, 'db.sqlite3')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your-secret-key'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    from .models import User  # ✅ Import your User model

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))  # ✅ Load user from DB by ID

    from .routes import main
    app.register_blueprint(main)

    return app
