import os


from flask import Flask
app = Flask(__name__)
app.config.from_pyfile(os.environ.get('SECFIXES_TRACKER_CONFIG', None), silent=False)


from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy(app)


from . import models
from . import importers