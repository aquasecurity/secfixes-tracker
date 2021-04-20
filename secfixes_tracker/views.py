from flask import render_template, request, jsonify


from . import app, db
from .models import Vulnerability, PackageVersion, Package


@app.route('/')
def show_index():
    return render_template('index.html')


@app.route('/branch')
def show_branch():
    branch = request.args.get('branch')
    pkgvers = PackageVersion.query.filter_by(repo=branch).all()
    pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
    return render_template('branch.html', branch=branch, pkgvers=pkgvers)


@app.route('/vuln/<cve_id>')
def show_vulnerability(cve_id):
    v = Vulnerability.query.filter_by(cve_id=cve_id).first_or_404()
    return render_template('vuln.html', vuln=v)


@app.route('/srcpkg/<package>')
def show_package(package):
    p = Package.query.filter_by(package_name=package).first_or_404()
    return render_template('package.html', package=p)