import pytest
import secfixes_tracker

from secfixes_tracker import views, models

@pytest.fixture(scope='module')
def app():
    app = secfixes_tracker.create_app(testing=True)
    models.register(app)
    views.register(app)
    
    with app.app_context():
        secfixes_tracker.db.create_all()
        yield app
        secfixes_tracker.db.drop_all()

@pytest.fixture(scope='module')
def db(app):
    return secfixes_tracker.db



