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

    @app.cli.command('export', help='Export individual CVE JSON files to data directory.')
    def export_data():
        import os
        import json
        from .models import Vulnerability, Package, PackageVersion, VulnerabilityState
        from flask import current_app
        
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        
        # Create a mock request context for JSON-LD generation
        with current_app.test_request_context():
            # Export only Alpine-relevant CVEs (CVEs with vulnerability states)
            # This filters out the 292k+ CVEs to only those that affect Alpine packages
            print('I: Filtering CVEs to only Alpine-relevant vulnerabilities...')
            
            # Get all CVEs that have vulnerability states (i.e., affect Alpine packages)
            alpine_vuln_ids = db.session.query(VulnerabilityState.vuln_id).distinct().all()
            alpine_vuln_ids = [v[0] for v in alpine_vuln_ids]
            
            print(f'I: Found {len(alpine_vuln_ids)} Alpine-relevant CVEs out of {Vulnerability.query.count()} total CVEs')
            
            # Export individual CVE files (only Alpine-relevant with valid CVE IDs)
            vulnerabilities = Vulnerability.query.filter(Vulnerability.vuln_id.in_(alpine_vuln_ids)).all()
            
            exported_count = 0
            skipped_count = 0
            
            for vuln in vulnerabilities:
                # Extract CVE ID from the vulnerability
                cve_id = vuln.cve_id
                
                # Only export if it's a valid CVE ID (CVE-YYYY-NNNNN format)
                # This filters out non-CVE entries like ALPINE-* or other formats
                if cve_id and cve_id.startswith('CVE-'):
                    # Create individual CVE file
                    cve_data = vuln.to_json()
                    filename = f"data/{cve_id}.json"
                    with open(filename, 'w') as f:
                        json.dump(cve_data, f, indent=2)
                    exported_count += 1
                else:
                    # Skip non-CVE entries (like ALPINE-* identifiers)
                    skipped_count += 1
                    if cve_id:
                        print(f'I: Skipping non-CVE entry: {cve_id}')
            
            # Note: Consolidated export files (vulnerabilities.json, packages.json, etc.) 
            # are not exported as they're not used downstream in vuln-list-update
        
        print(f"I: Export completed successfully!")
        print(f"I: Exported {exported_count} CVE files (Alpine-relevant only)")
        if skipped_count > 0:
            print(f"I: Skipped {skipped_count} non-CVE entries (e.g., ALPINE-* identifiers)")
        print(f"I: Total CVEs in database: {Vulnerability.query.count()}")
        print(f"I: Alpine-relevant vulnerabilities found: {len(alpine_vuln_ids)}")
