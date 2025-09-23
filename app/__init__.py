import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf import CSRFProtect

csrf = CSRFProtect()
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # ---- Configurations ----
    db_path = os.path.join(app.instance_path, 'db.sqlite3')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your-secret-key'

    # Email configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'netwebzmin25@gmail.com'
    app.config['MAIL_PASSWORD'] = 'ksvr srix redg tgaa'  # App password
    app.config['MAIL_DEFAULT_SENDER'] = ('Netwitz Admin', 'netwebzmin25@gmail.com')

    # ---- Extensions Initialization ----
    db.init_app(app)
    Migrate(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'main.login'

    # ---- Models ----
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---- Blueprints ----
    from .routes import main
    app.register_blueprint(main)

    return app


