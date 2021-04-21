import click
import json
import gzip
import uuid
import requests
import tarfile
import tempfile


from io import TextIOWrapper
from pprint import pprint
from . import app, db
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch, VulnerabilityReference
from .version import APKVersion


@app.cli.command('import-nvd', help='Import a NVD feed.')
@click.argument('name')
def import_nvd_cve(name: str):
    uri = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{name}.json.gz'

    print(f'I: Importing NVD feed [{name}] from [{uri}].')

    r = requests.get(uri)
    payload = r.content

    print(f'I: Downloaded {len(payload)} bytes.')

    data = gzip.decompress(payload).decode()
    data = json.loads(data)

    if 'CVE_Items' not in data:
        print(f'E: CVE_Items not found in NVD feed.')
        exit(1)

    for item in data['CVE_Items']:
        process_nvd_cve_item(item)

    print(f'I: Imported NVD feed successfully.')


def process_nvd_cve_reference(vuln: Vulnerability, item: dict):
    ref_type = item['refsource']
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
    db.session.commit()


def process_nvd_cve_item(item: dict):
    if 'cve' not in item:
        return

    cve = item['cve']
    cve_meta = cve.get('CVE_data_meta', {})
    cve_id = cve_meta.get('ID', None)

    if not cve_id:
        return

    cve_description = cve.get('description', {}).get('description_data', [])
    if not cve_description:
        return

    cve_description_text = cve_description[0]['value']
    print(f'I: Processing {cve_id}.')

    impact = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})

    cvss3_score = impact.get('baseScore', None)
    cvss3_vector = impact.get('vectorString', None)

    vuln = Vulnerability.find_or_create(cve_id)
    vuln.description = cve_description_text
    vuln.cvss3_score = cvss3_score
    vuln.cvss3_vector = cvss3_vector

    db.session.add(vuln)
    db.session.commit()

    if 'configurations' in item:
        process_nvd_cve_configurations(vuln, item['configurations'])

    if 'references' in cve:
        process_nvd_cve_references(vuln, cve['references']['reference_data'])


rewrite_python = lambda x: 'py3-' + x.replace('_', '-').lower()
rewrite_ruby = lambda x: 'ruby-' + x.replace('_', '-').lower()
rewrite_perl = lambda x: 'perl-' + x.replace('_', '-').replace('::', '-').lower()
rewrite_lua = lambda x: 'lua-' + x.replace('_', '-').lower()


REWRITERS = {
    'python': rewrite_python,
    'ruby': rewrite_ruby,
    'perl': rewrite_perl,
    'lua': rewrite_lua,
}


def process_nvd_cve_configurations(vuln: Vulnerability, configuration: dict):
    global REWRITERS

    if 'nodes' not in configuration or not configuration['nodes']:
        return

    nodes = configuration['nodes']
    if not nodes or 'cpe_match' not in nodes[0]:
        return

    cpe_match = nodes[0]['cpe_match']

    for match in cpe_match:
        if 'cpe23Uri' not in match:
            continue

        # if vulnerable is not specified, assume True.  maintainer can override
        # by adding a secfixes-override entry in their APKBUILD.
        cpe_uri = match.get('cpe23Uri')
        vulnerable = match.get('vulnerable', True)

        cpe_parts = cpe_uri.split(':')[3:6]
        cpe_language = cpe_uri.split(':')[10].lower()

        rewriter = REWRITERS.get(cpe_language, None)

        # TODO: implement source_pkgname overrides in app.config
        source_pkgname = cpe_parts[1]
        if rewriter:
            source_pkgname = rewriter(source_pkgname)

        source_version = cpe_parts[2] if cpe_parts[2] != '*' else None

        process_nvd_cve_configuration_item(vuln, source_pkgname, source_version, vulnerable)


def process_nvd_cve_configuration_item(vuln: Vulnerability, source_pkgname: str, source_version: str, vulnerable: bool):
    pkg = Package.find_or_create(source_pkgname)
    db.session.add(pkg)
    db.session.commit()

    cm = CPEMatch.find_or_create(pkg, vuln, source_version, vulnerable)
    db.session.add(cm)
    db.session.commit()


@app.cli.command('import-secfixes', help='Import secfixes feeds.')
def import_secfixes():
    for repo, uri in app.config.get('SECFIXES_REPOSITORIES', {}).items():
        import_secfixes_feed(repo, uri)


def import_secfixes_feed(repo: str, uri: str):
    print(f'I: [{repo}] Downloading {uri}')

    r = requests.get(uri)
    data = r.json()

    packages = data.get('packages', [])

    for package in packages:
        import_secfixes_package(repo, package['pkg'])


def import_secfixes_package(repo: str, package: dict):
    pkg = Package.find_or_create(package['name'])
    db.session.add(pkg)

    secfixes = package.get('secfixes', {})
    for ver, fixes in secfixes.items():
        pkgver = PackageVersion.find_or_create(pkg, ver, repo)
        db.session.add(pkgver)
        db.session.commit()

        for fix in fixes:
            fix = fix.split()[0]
            vuln = Vulnerability.find_or_create(fix)
            db.session.add(vuln)
            db.session.commit()

            state = VulnerabilityState.find_or_create(pkgver, vuln)
            state.fixed = True

            db.session.add(state)
            db.session.commit()


@app.cli.command('import-apkindex', help='Import APK repository indices.')
def import_apkindex():
    for repo, uri in app.config.get('APKINDEX_REPOSITORIES', {}).items():
        import_apkindex_repo(repo, uri)


def import_apkindex_repo(repo: str, uri: str):
    print(f'I: [{repo}] Downloading {uri}')

    r = requests.get(uri)

    with tempfile.TemporaryFile() as f:
        f.write(r.content)
        f.seek(0)

        import_apkindex_payload(repo, f)


def import_apkindex_pkg(pkg: dict, repo: str):
    p = Package.find_or_create(pkg['o'])
    db.session.add(p)
    db.session.commit()

    pkgver = PackageVersion.find_or_create(p, pkg['V'], repo)
    pkgver.published = True

    if pkg['o'] == pkg['P']:
        pkgver.maintainer = pkg.get('m', None)

    db.session.add(pkgver)
    db.session.commit()


def import_apkindex_idx(index_data, repo: str):
    current_pkg = {}

    for line in index_data:
        data = line.strip().split(':', 1)

        if len(data) == 1:
            import_apkindex_pkg(current_pkg, repo)
            current_pkg = {}
        else:
            current_pkg[data[0]] = data[1]


def import_apkindex_payload(repo: str, file):
    print(f'I: [{repo}] Processing APKINDEX')

    with tarfile.open(mode='r', fileobj=file, debug=3) as tf:
        for tarentry in tf.getmembers():
            if tarentry.name == 'APKINDEX':
                data = tf.extractfile(tarentry)
                import_apkindex_idx(TextIOWrapper(data), repo)


@app.cli.command('update-states', help='Update the package vulnerability states.')
def update_states():
    for repo, _ in app.config.get('SECFIXES_REPOSITORIES', {}).items():
        update_states_for_repo_tag(repo)


def update_states_for_repo_tag(repo: str):
    print(f'I: [{repo}] Processing updates.')

    for pkgver in PackageVersion.query.filter_by(repo=repo, published=True):
        update_states_for_pkgver(pkgver)


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
    # XXX: We need to find the lowest fixed version ideally.
    fixed_state = VulnerabilityState.query.filter_by(vuln_id=vuln.vuln_id, fixed=True).first()
    fixed = False
    if not fixed_state:
        print(f'I: No fix recorded against any {pkgver.package} version for {vuln}')
    else:
        print(f'I: Fix recorded in {fixed_state.package_version} for {vuln}')

        fv = fixed_state.package_version
        fixed = pv >= fv

    vuln_state = VulnerabilityState.find_or_create(pkgver, vuln)
    if vuln_state.fixed:
        return

    vuln_state.fixed = fixed
    db.session.add(vuln_state)
    db.session.commit()