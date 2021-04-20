from flask import render_template


from . import app, db
from .models import Vulnerability


@app.route('/')
def show_index():
    return render_template('index.html')


@app.route('/vuln/<cve_id>')
def show_vulnerability(cve_id):
    v = Vulnerability.query.filter_by(cve_id=cve_id).first_or_404()
    return render_template('vuln.html', vuln=v)