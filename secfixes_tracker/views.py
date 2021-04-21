from flask import render_template, request, jsonify
from flask_accept import accept


from . import app, db
from .models import Vulnerability, PackageVersion, Package


@app.route('/')
@accept('text/html')
def show_index():
    return render_template('index.html')


@app.route('/branch')
def show_branch():
    branch = request.args.get('branch')
    pkgvers = PackageVersion.query.filter_by(repo=branch).all()
    pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
    title = f'Potentially vulnerable packages in {branch}'
    return render_template('branch.html', title=title, branch=branch, pkgvers=pkgvers)


@app.route('/branch/vuln-orphaned')
def show_orphaned_vulns_for_branch():
    branch = request.args.get('branch')
    pkgvers = PackageVersion.query.filter_by(repo=branch, published=True, maintainer=None).all()
    pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
    title = f'Potentially vulnerable orphaned packages in {branch}'
    return render_template('branch.html', title=title, branch=branch, pkgvers=pkgvers)


@app.route('/branch/orphaned')
def show_orphaned_for_branch():
    branch = request.args.get('branch')
    pkgvers = PackageVersion.query.filter_by(repo=branch, published=True, maintainer=None).all()
    title = f'Orphaned packages in {branch}'
    return render_template('branch-orphaned.html', title=title, branch=branch, pkgvers=pkgvers)


@app.route('/maintainer-issues')
def show_maintainer_issues():
    branch = request.args.get('branch')
    maint = request.args.get('maintainer', None)

    pkgvers = PackageVersion.query.filter_by(repo=branch, published=True)
    if maint:
        pkgvers = pkgvers.filter_by(maintainer=maint)
    pkgvers = pkgvers.order_by(PackageVersion.maintainer).all()
    pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]

    title = f'Issues by maintainer for {branch}'
    return render_template('branch-maintainer.html', title=title, branch=branch, pkgvers=pkgvers)


@app.route('/vuln/<cve_id>')
@accept('text/html')
def show_vulnerability(cve_id):
    v = Vulnerability.query.filter_by(cve_id=cve_id).first_or_404()
    return render_template('vuln.html', vuln=v)


@show_vulnerability.support('application/json')
@show_vulnerability.support('application/ld+json')
def show_vulnerability_json_ld(cve_id):
    v = Vulnerability.query.filter_by(cve_id=cve_id).first_or_404()
    return jsonify(v.to_json_ld())


@app.route('/srcpkg/<package>')
@accept('text/html')
def show_package(package):
    p = Package.query.filter_by(package_name=package).first_or_404()
    return render_template('package.html', package=p)


@show_package.support('application/json')
@show_package.support('application/ld+json')
def show_package_json_ld(package):
    p = Package.query.filter_by(package_name=package).first_or_404()
    return jsonify(p.to_json_ld())


@app.route('/srcpkg/<package>/<version>')
@accept('application/json')
@accept('application/ld+json')
def show_package_version_json_ld(package, version):
    p = Package.query.filter_by(package_name=package).first_or_404()
    pv = PackageVersion.query.filter_by(package_id=p.package_id, version=version).first_or_404()
    return jsonify(pv.to_json_ld())