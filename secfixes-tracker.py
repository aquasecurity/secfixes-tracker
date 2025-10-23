from secfixes_tracker import create_app

app = create_app()

from secfixes_tracker import models, importers, views

models.register(app)
importers.register(app)
views.register(app)

