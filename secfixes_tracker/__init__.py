import os

from flask import Flask

from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


def create_app(testing=False):
    app = Flask(__name__)
    if testing:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SERVER_NAME'] = 'localhost'
        app.config['SECFIXES_REPOSITORIES'] = {}
    else:
        app.config.from_pyfile(os.environ.get('SECFIXES_TRACKER_CONFIG', None), silent=False)

    app.config["SECFIXES_TRACKER_VERSION"] = "0.4.1"

    db.init_app(app)
    return app
