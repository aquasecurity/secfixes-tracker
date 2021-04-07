import click
import json
import gzip
import uuid
import requests


from pprint import pprint
from . import app, db
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState


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

    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
    if not vuln:
        vuln = Vulnerability()

    vuln.cve_id = cve_id
    vuln.description = cve_description_text
    vuln.cvss3_score = cvss3_score
    vuln.cvss3_vector = cvss3_vector

    db.session.add(vuln)
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
