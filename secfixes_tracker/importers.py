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
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch


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


def process_nvd_cve_configurations(vuln: Vulnerability, configuration: dict):
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

        # TODO: implement source_pkgname overrides in app.config
        source_pkgname = cpe_parts[1]
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