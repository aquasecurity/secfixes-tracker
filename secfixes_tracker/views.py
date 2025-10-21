from flask import render_template, request, jsonify, url_for
from flask_accept import accept


from . import db
from .models import Vulnerability, PackageVersion, Package


def register(app):
    @app.route('/')
    @accept('text/html')
    def show_index():
        return render_template('index.html')

    @show_index.support('application/json')
    @show_index.support('application/ld+json')
    def show_index_json_ld():
        branches = {}
        for branch in app.config.get('SECFIXES_REPOSITORIES', {}).keys():
            branches[branch] = {
                "potentiallyVulnerablePackages": f'https://{request.host}{url_for("show_branch", branch=branch)}',
                "potentiallyOrphanedVulnerablePackages": f'https://{request.host}{url_for("show_orphaned_vulns_for_branch", branch=branch)}',
                "orphanedPackages": f'https://{request.host}{url_for("show_orphaned_for_branch", branch=branch)}',
                "issuesByMaintainer": f'https://{request.host}{url_for("show_maintainer_issues", branch=branch)}',
            }
        return jsonify(branches)

    def show_collection_json_ld(pkgvers: list):
        resp = {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': f'https://{request.host}{request.path}',
            'type': 'Collection',
            'items': [vuln.to_json_ld() for pkgver in pkgvers for vuln in pkgver.vulnerabilities()]
        }
        return jsonify(resp)

    @app.route('/branch/<branch>')
    @accept('text/html')
    def show_branch(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
        title = f'Potentially vulnerable packages in {branch}'
        return render_template('branch.html', title=title, branch=branch, pkgvers=pkgvers)

    @show_branch.support('application/json')
    @show_branch.support('application/ld+json')
    def show_branch_json_ld(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
        return show_collection_json_ld(pkgvers)

    @app.route('/branch/<branch>/vuln-orphaned')
    @accept('text/html')
    def show_orphaned_vulns_for_branch(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True, maintainer=None).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
        title = f'Potentially vulnerable orphaned packages in {branch}'
        return render_template('branch.html', title=title, branch=branch, pkgvers=pkgvers)

    @show_orphaned_vulns_for_branch.support('application/json')
    @show_orphaned_vulns_for_branch.support('application/ld+json')
    def show_orphaned_vulns_for_branch_json_ld(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True, maintainer=None).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
        return show_collection_json_ld(pkgvers)

    @app.route('/branch/<branch>/orphaned')
    @accept('text/html')
    def show_orphaned_for_branch(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True, maintainer=None).all()
        title = f'Orphaned packages in {branch}'
        return render_template('branch-orphaned.html', title=title, branch=branch, pkgvers=pkgvers)

    @show_orphaned_for_branch.support('application/json')
    @show_orphaned_for_branch.support('application/ld+json')
    def show_orphaned_for_branch_json_ld(branch):
        pkgvers = PackageVersion.query.filter_by(
            repo=branch, published=True, maintainer=None).all()
        resp = {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': f'https://{request.host}{request.path}',
            'type': 'Collection',
            'items': [pkgver.to_json_ld() for pkgver in pkgvers]
        }
        return jsonify(resp)

    @app.route('/branch/<branch>/maintainer-issues')
    @accept('text/html')
    def show_maintainer_issues(branch):
        maint = request.args.get('maintainer', None)

        pkgvers = PackageVersion.query.filter_by(repo=branch, published=True)
        if maint:
            pkgvers = pkgvers.filter_by(maintainer=maint)
        pkgvers = pkgvers.order_by(PackageVersion.maintainer).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]

        title = f'Issues by maintainer for {branch}'
        return render_template('branch-maintainer.html', title=title, branch=branch, pkgvers=pkgvers)

    @show_maintainer_issues.support('application/json')
    @show_maintainer_issues.support('application/ld+json')
    def show_maintainer_issues_json_ld(branch):
        maint = request.args.get('maintainer', None)

        pkgvers = PackageVersion.query.filter_by(repo=branch, published=True)
        if maint:
            pkgvers = pkgvers.filter_by(maintainer=maint)
        pkgvers = pkgvers.order_by(PackageVersion.maintainer).all()
        pkgvers = [pkgver for pkgver in pkgvers if pkgver.is_vulnerable()]
        return show_collection_json_ld(pkgvers)

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
        pv = PackageVersion.query.filter_by(
            package_id=p.package_id, version=version).first_or_404()
        return jsonify(pv.to_json_ld())

    @app.cli.command('export', help='Export JSON files to data directory.')
    def export_data():
        import os
        import json
        from .models import Vulnerability, Package, PackageVersion, VulnerabilityState
        
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        
        # Export vulnerabilities
        vulnerabilities = Vulnerability.query.all()
        vuln_data = [v.to_json_ld() for v in vulnerabilities]
        with open('data/vulnerabilities.json', 'w') as f:
            json.dump(vuln_data, f, indent=2)
        
        # Export packages
        packages = Package.query.all()
        pkg_data = [p.to_json_ld() for p in packages]
        with open('data/packages.json', 'w') as f:
            json.dump(pkg_data, f, indent=2)
        
        # Export package versions
        package_versions = PackageVersion.query.all()
        pkgver_data = [pv.to_json_ld() for pv in package_versions]
        with open('data/package_versions.json', 'w') as f:
            json.dump(pkgver_data, f, indent=2)
        
        # Export vulnerability states
        vuln_states = VulnerabilityState.query.all()
        state_data = [vs.to_json_ld() for vs in vuln_states]
        with open('data/vulnerability_states.json', 'w') as f:
            json.dump(state_data, f, indent=2)
        
        print("Export completed successfully!")
