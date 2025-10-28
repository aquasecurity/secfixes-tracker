import click
import datetime
import json
import gzip
import requests
import tarfile
import tempfile
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


from io import TextIOWrapper
from . import db
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch, VulnerabilityReference
from .version import APKVersion
from . import nvd


def rewrite_python(x): return 'py3-' + x.replace('_', '-').lower()
def rewrite_ruby(x): return 'ruby-' + x.replace('_', '-').lower()
def rewrite_perl(x): return 'perl-' + x.replace('_',
                                                '-').replace('::', '-').lower()


def rewrite_lua(x): return 'lua-' + x.replace('_', '-').lower()
def rewrite_vscode(x): return 'vscode-' + x.replace('_', '-').lower()


LANGUAGE_REWRITERS = {
    'python': rewrite_python,
    'ruby': rewrite_ruby,
    'perl': rewrite_perl,
    'lua': rewrite_lua,
    'visual_studio_code': rewrite_vscode,
}


def register(app):
    
    @app.cli.command('import-nvd', help='Import a NVD feed.')
    @click.argument('days')
    def import_nvd_cve(days: str):
        api = nvd.API()

        print(f'I: Importing NVD changes from {days} day(s) ago')

        cve_resp = api.cves(
            last_mod_start_date=datetime.datetime.now() - datetime.timedelta(days=int(days)),
            last_mod_end_date=datetime.datetime.now(),
        )

        if 'vulnerabilities' not in cve_resp:
            print(f"E: 'vulnerabilities' not found in NVD feed.")
            exit(1)

        for item in cve_resp['vulnerabilities']:
            process_nvd_cve_item(item)

        db.session.commit()
        print(f'I: Imported NVD feed successfully.')

    @app.cli.command('import-nvd-files', help='Import NVD CVEs from local JSON files.')
    @click.argument('directory')  
    def import_nvd_files(directory: str):
        """Import NVD CVEs from local JSON files using original Alpine logic"""
        import os
        import json
        import glob
        
        if not os.path.exists(directory):
            print(f'E: Directory {directory} does not exist.')
            return
        
        # Find all CVE JSON files in the directory
        cve_files = glob.glob(os.path.join(directory, 'CVE-*.json'))
        
        if not cve_files:
            print(f'I: No CVE files found in {directory}')
            return
        
        print(f'I: Processing {len(cve_files)} CVE files from {directory} using original Alpine logic')
        
        processed_count = 0
        skipped_count = 0
        
        for i, cve_file in enumerate(cve_files, 1):
            try:
                with open(cve_file, 'r') as f:
                    cve_data = json.load(f)
                
                # Adapt vuln-list-nvd format to original process_nvd_cve_item expectations
                # vuln-list-nvd: {"id": "CVE-...", "descriptions": [...], "metrics": {...}}
                # process_nvd_cve_item expects: {"cve": {"id": "CVE-...", "descriptions": [...], "metrics": {...}}}
                adapted_item = {"cve": cve_data}
                
                # Use original Alpine logic for processing
                process_nvd_cve_item(adapted_item)
                processed_count += 1
                
                # Progress reporting
                if i % 1000 == 0:
                    print(f'I: Progress: {i}/{len(cve_files)} files processed ({(i/len(cve_files)*100):.1f}%)')
                
            except Exception as e:
                skipped_count += 1
                if skipped_count <= 5:  # Only show first few errors
                    print(f'W: Error processing {cve_file}: {e}')
        
        # Single commit at the end for the entire directory
        db.session.commit()
        
        print(f'I: Processed {processed_count} CVEs from local files using original Alpine logic')
        if skipped_count > 0:
            print(f'W: Skipped {skipped_count} files due to errors')

    def process_nvd_cve_reference(vuln: Vulnerability, item: dict):
        ref_type = item['source']
        ref_tags = item.get('tags', [])

        ref_uri = item.get('url', None)
        if not ref_uri:
            return

        if ref_tags:
            ref_type = ref_tags[0]

        ref = VulnerabilityReference.find_or_create(vuln, ref_type, ref_uri)
        db.session.add(ref)

    def process_nvd_cve_references(vuln: Vulnerability, refs: list):
        [process_nvd_cve_reference(vuln, item) for item in refs]

    def process_nvd_cve_item(item: dict):
        if 'cve' not in item:
            return

        cve = item['cve']
        cve_id = cve.get('id', None)

        if not cve_id:
            return

        cve_description = select(
            cve.get('descriptions', []),
            lambda desc: desc['lang'] == "en"
        ).get('value', [])
        if not cve_description:
            return

        print(f'I: Processing {cve_id}.')

        impact = item.get('metrics', {}).get(
            'cvssMetricV31', {}).get('cvssData', {})

        cvss3_score = impact.get('baseScore', None)
        cvss3_vector = impact.get('vectorString', None)

        vuln = Vulnerability.find_or_create(cve_id)
        vuln.description = cve_description
        vuln.cvss3_score = cvss3_score
        vuln.cvss3_vector = cvss3_vector

        db.session.add(vuln)

        if 'configurations' in cve and len(cve['configurations']) > 0:
            process_nvd_cve_configurations(vuln, cve['configurations'][0])

        if 'references' in cve:
            process_nvd_cve_references(vuln, cve['references'])

    def match_uses_version_ranges(match: dict) -> bool:
        version_match_keywords = {
            'versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'}
        return version_match_keywords & set(match.keys()) != set()

    def process_nvd_cve_configurations(vuln: Vulnerability, configuration: dict):
        global LANGUAGE_REWRITERS
        if 'nodes' not in configuration or not configuration['nodes']:
            return
        nodes = configuration['nodes']
        if not nodes or 'cpeMatch' not in nodes[0]:
            return
        cpe_match = nodes[0]['cpeMatch']
        for match in cpe_match:
            if 'criteria' not in match:
                continue
            cpe_uri = match.get('criteria')
            vulnerable = match.get('vulnerable', True)
            cpe_parts = cpe_uri.split(':')[3:6]
            cpe_language = cpe_uri.split(':')[10].lower()
            language_rewriter = LANGUAGE_REWRITERS.get(cpe_language, None)
            source_pkgname = cpe_parts[1]
            if language_rewriter:
                source_pkgname = language_rewriter(source_pkgname)
            cpe_vendor = cpe_parts[0]
            custom_rewriters = app.config.get('CUSTOM_REWRITERS', {})
            custom_rewriter_key = f'{cpe_vendor}:{source_pkgname}'
            custom_rewriter = custom_rewriters.get(custom_rewriter_key,
                                                   custom_rewriters.get(f'{cpe_vendor}:*', None))
            if custom_rewriter:
                source_pkgname = custom_rewriter(source_pkgname)
            source_version = cpe_parts[2] if cpe_parts[2] != '*' else None
            using_version_ranges = match_uses_version_ranges(match)
            max_version = match.get('versionEndIncluding', match.get(
                'versionEndExcluding', source_version))
            min_version = match.get('versionStartIncluding', match.get(
                'versionStartExcluding', None))
            min_version_op = '=='
            max_version_op = '=='
            if using_version_ranges:
                min_version_op = '>='
                if 'versionStartExcluding' in match:
                    min_version_op = '>'
                max_version_op = '<='
                if 'versionEndExcluding' in match:
                    max_version_op = '<'
            process_nvd_cve_configuration_item(
                vuln, source_pkgname, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)

    def process_nvd_cve_configuration_item(vuln: Vulnerability, source_pkgname: str,
                                           min_version: str, min_version_op: str,
                                           max_version: str, max_version_op: str, vulnerable: bool, cpe_uri: str):
        pkg = Package.find_or_create(source_pkgname)
        db.session.add(pkg)

        cm = CPEMatch.find_or_create(
            pkg, vuln, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)
        db.session.add(cm)

    @app.cli.command('import-secfixes', help='Import secfixes feeds.')
    @click.argument('repo', required=False)
    def import_secfixes(repo: str):
        repositories = app.config.get('SECFIXES_REPOSITORIES', {})

        if not repositories:
            print("E: No SECFIXES_REPOSITORIES configured.")
            exit(1)

        if repo:
            uri = repositories.get(repo)
            if uri:
                import_secfixes_feed(repo, uri)
                return

            print(f"E: Repository {repo} not found in SECFIXES_REPOSITORIES.")
            exit(1)

        for repo, uri in repositories.items():
            import_secfixes_feed(repo, uri)

    def import_secfixes_feed(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)
        data = r.json()

        packages = data.get('packages', [])

        for package in packages:
            import_secfixes_package(repo, package['pkg'])
        db.session.commit()

    def import_secfixes_package(repo: str, package: dict):
        pkg = Package.find_or_create(package['name'])
        db.session.add(pkg)

        secfixes = package.get('secfixes', {})
        for ver, fixes in secfixes.items():
            pkgver = PackageVersion.find_or_create(pkg, ver, repo)
            db.session.add(pkgver)

            for fix in fixes:
                fix = fix.split()[0]
                vuln = Vulnerability.find_or_create(fix)
                db.session.add(vuln)

                state = VulnerabilityState.find_or_create(pkgver, vuln)
                state.fixed = True

                db.session.add(state)

    @app.cli.command('import-rejections', help='Import security rejections feeds.')
    @click.argument('repo', required=False)
    def import_security_rejections(repo: str):
        repositories = app.config.get('SECURITY_REJECTIONS', {})
        if repo:
            uri = repositories.get(repo)
            if uri:
                import_security_rejections_feed(repo, uri)
                return

            print(f"E: Repository {repo} not found in SECURITY_REJECTIONS.")
            exit(1)

        for repo, uri in app.config.get('SECURITY_REJECTIONS', {}).items():
            import_security_rejections_feed(repo, uri)

    def import_security_rejections_feed(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)

        try:
            feed = yaml.load(r.content, Loader=yaml.SafeLoader)
            [import_security_rejections_package(
                repo, k, v) for k, v in feed.items()]
        except Exception as e:
            print(
                f'E: Encountered {e} while parsing security rejections feed.')
            exit(1)

        db.session.commit()

    def import_security_rejections_package(repo: str, pkgname: str, cves: list):
        pkg = Package.find_or_create(pkgname)
        db.session.add(pkg)

        pkgver = PackageVersion.find_or_create(pkg, '0', repo)
        db.session.add(pkgver)

        for cve in cves:
            vuln = Vulnerability.find_or_create(cve)
            db.session.add(vuln)

            state = VulnerabilityState.find_or_create(pkgver, vuln)
            state.fixed = True

            db.session.add(state)

    @app.cli.command('import-apkindex', help='Import APK repository indices.')
    @click.argument('repo', required=False)
    def import_apkindex(repo: str):
        repositories = app.config.get('APKINDEX_REPOSITORIES', {})

        if repo:
            uri = repositories.get(repo)
            if uri:
                import_apkindex_repo(repo, uri)
                return

            print(f"E: Repository {repo} not found in APKINDEX_REPOSITORIES.")
            exit(1)

        for repo, uri in repositories.items():
            import_apkindex_repo(repo, uri)

    def import_apkindex_repo(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)

        with tempfile.TemporaryFile() as f:
            f.write(r.content)
            f.seek(0)

            import_apkindex_payload(repo, f)

    def import_apkindex_pkg(pkg: dict, repo: str):
        origin = pkg.get('o', pkg['P'])
        p = Package.find_or_create(origin)
        db.session.add(p)

        pkgver = PackageVersion.find_or_create(p, pkg['V'], repo)
        pkgver.published = True

        if origin == pkg['P']:
            pkgver.maintainer = pkg.get('m', None)

        db.session.add(pkgver)

    def import_apkindex_idx(index_data, repo: str):
        current_pkg = {}

        for line in index_data:
            data = line.strip().split(':', 1)

            if len(data) == 1:
                import_apkindex_pkg(current_pkg, repo)
                current_pkg = {}
            else:
                current_pkg[data[0]] = data[1]
        db.session.commit()

    def import_apkindex_payload(repo: str, file):
        print(f'I: [{repo}] Processing APKINDEX')

        with tarfile.open(mode='r', fileobj=file, debug=3) as tf:
            for tarentry in tf.getmembers():
                if tarentry.name == 'APKINDEX':
                    data = tf.extractfile(tarentry)
                    import_apkindex_idx(TextIOWrapper(data), repo)

    @app.cli.command('update-states', help='Update the package vulnerability states.')
    @click.argument('repo', required=False)
    def update_states(repo: str):
        repositories = app.config.get('SECFIXES_REPOSITORIES', {})
        if repo:
            if not repositories.get(repo):
                print(
                    f"E: Repository {repo} not found in SECFIXES_REPOSITORIES.")
                exit(1)

            update_states_for_repo_tag(repo)
            return

        for repo, _ in repositories.items():
            update_states_for_repo_tag(repo)

    def update_states_for_repo_tag(repo: str):
        print(f'I: [{repo}] Processing updates.')

        for pkgver in PackageVersion.query.filter_by(repo=repo, published=True):
            update_states_for_pkgver(pkgver)
        db.session.commit()

    def update_states_for_pkgver(pkgver: PackageVersion):
        pkg = pkgver.package

        print(f'I: Considering {pkgver} ({pkg})')

        # walk the CPE matches to find associated vulnerabilities
        for cpe_match in pkg.cpe_matches:
            update_states_if_pkgver_matches_cpe_match(pkgver, cpe_match)

    def update_states_if_pkgver_matches_cpe_match(pkgver: PackageVersion, cpe_match: CPEMatch):
        vuln = cpe_match.vuln
        pv = APKVersion(pkgver.version)

        print(f'I: Evaluating {cpe_match} for {vuln} against {pkgver}')

        if not cpe_match.matches_version(pkgver):
            print(f'I: CPE match does not match {pkgver}')
            return

        # Look for a fixed VulnerabilityState that is older than pkgver.
        fixed_states = VulnerabilityState.query.filter_by(
            vuln_id=vuln.vuln_id, fixed=True).all()
        fixed_states = [
            state for state in fixed_states if state.package_version.repo == pkgver.repo]
        fixed_states = sorted(
            fixed_states, key=lambda x: APKVersion(x.package_version.version))

        fixed_state = fixed_states[0] if fixed_states else None
        fixed = False
        if not fixed_state:
            print(
                f'I: No fix recorded against any {pkgver.package} version for {vuln}')
        else:
            print(
                f'I: Fix recorded in {fixed_state.package_version} for {vuln}')

            fv = APKVersion(fixed_state.package_version.version)
            fixed = pv >= fv

        vuln_state = VulnerabilityState.find_or_create(pkgver, vuln)
        if vuln_state.fixed:
            return

        vuln_state.fixed = fixed
        db.session.add(vuln_state)


def select(lst, predicate):
    for elem in lst:
        if predicate(elem):
            return elem
    return {}
