# tests/unit/test_models.py

import pytest
from secfixes_tracker.models import Vulnerability, VulnerabilityReference, Package, PackageVersion


def test_vulnerability_create(db):
    vuln = Vulnerability(cve_id="CVE-2023-12345",
                         description="Test vulnerability")
    db.session.add(vuln)
    db.session.commit()

    retrieved_vuln = Vulnerability.query.filter_by(
        cve_id="CVE-2023-12345").first()
    assert repr(retrieved_vuln) == "<Vulnerability CVE-2023-12345>"
    assert retrieved_vuln.description == "Test vulnerability"


def test_vunlerability_find_or_create(db):
    # Try to find a non-existent cve_id
    vuln = Vulnerability.find_or_create('CVE-2023-0001')
    assert vuln.cve_id == 'CVE-2023-0001'

    # Add to db and commit
    db.session.add(vuln)
    db.session.commit()

    # Try to find the added cve_id
    existing_vuln = Vulnerability.find_or_create('CVE-2023-0001')
    assert existing_vuln.vuln_id == vuln.vuln_id


def test_vulnerability_json_ld_id(app, db):
    vuln = Vulnerability(cve_id='CVE-2023-0002')
    db.session.add(vuln)
    db.session.commit()

    with app.test_request_context('/'):
        assert vuln.json_ld_id == f'https://{app.config["SERVER_NAME"]}/vuln/CVE-2023-0002'


def test_vulnerability_to_json_ld(app, db):
    vuln = Vulnerability(
        cve_id='CVE-2023-0003',
        description='Test vulnerability',
        cvss3_score=5.5,
        cvss3_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    )
    db.session.add(vuln)
    db.session.commit()

    with app.test_request_context('/'):
        json_ld = vuln.to_json_ld()
        assert json_ld['type'] == 'Vulnerability'
        assert json_ld['id'] == f'https://{app.config["SERVER_NAME"]}/vuln/CVE-2023-0003'
        assert json_ld['description'] == 'Test vulnerability'
        assert json_ld['cvss3']['score'] == 5.5
        # ... Test other fields as necessary ...


def test_vulnerability_to_nvd_severity(db):
    # Test when cvss3_score is None
    vuln = Vulnerability(cve_id='CVE-2023-0005')
    assert vuln.to_nvd_severity() == 'unknown'

    # Test when cvss3_score is greater than 8.0
    vuln = Vulnerability(cve_id='CVE-2023-0006', cvss3_score=9.0)
    assert vuln.to_nvd_severity() == 'high'

    # Test when cvss3_score is between 4.0 and 8.0
    vuln = Vulnerability(cve_id='CVE-2023-0007', cvss3_score=6.0)
    assert vuln.to_nvd_severity() == 'medium'

    # Test when cvss3_score is equal to 8.0 (edge case)
    vuln = Vulnerability(cve_id='CVE-2023-0008', cvss3_score=8.0)
    # it should still be medium since the condition checks for > 8.0 for high
    assert vuln.to_nvd_severity() == 'medium'

    # Test when cvss3_score is equal to 4.0 (edge case)
    vuln = Vulnerability(cve_id='CVE-2023-0009', cvss3_score=4.0)
    # it should be low since the condition checks for > 4.0 for medium
    assert vuln.to_nvd_severity() == 'low'

    # Test when cvss3_score is less than 4.0
    vuln = Vulnerability(cve_id='CVE-2023-0010', cvss3_score=3.0)
    assert vuln.to_nvd_severity() == 'low'


def test_vulnerabilityreference_find_or_create(db):
    vuln = Vulnerability(cve_id='CVE-2023-0015')
    db.session.add(vuln)
    db.session.commit()

    # Try to find a non-existent reference
    ref_uri = 'https://example.com/vulnerabilities/CVE-2023-0015'
    ref_type = 'web'
    ref = VulnerabilityReference.find_or_create(vuln, ref_type, ref_uri)

    assert ref.vuln_id == vuln.vuln_id
    assert ref.ref_type == ref_type
    assert ref.ref_uri == ref_uri

    # Add to db and commit
    db.session.add(ref)
    db.session.commit()

    # Try to find the added reference
    existing_ref = VulnerabilityReference.find_or_create(
        vuln, ref_type, ref_uri)
    assert existing_ref.vuln_ref_id == ref.vuln_ref_id


def test_vulnerabilityreference_json_ld_id(app, db):
    vuln = Vulnerability(cve_id='CVE-2023-0016')
    db.session.add(vuln)
    db.session.commit()

    ref_uri = 'https://example.com/vulnerabilities/CVE-2023-0016'
    ref_type = 'web'
    ref = VulnerabilityReference(
        vuln_id=vuln.vuln_id, ref_type=ref_type, ref_uri=ref_uri)
    db.session.add(ref)
    db.session.commit()

    with app.test_request_context('/'):
        expected_json_ld_id = f'https://{app.config["SERVER_NAME"]}/vuln/CVE-2023-0016#ref/{ref.vuln_ref_id}'
        assert ref.json_ld_id == expected_json_ld_id


def test_to_json_ld(app, db):
    vuln = Vulnerability(cve_id='CVE-2023-0017')
    db.session.add(vuln)
    db.session.commit()

    ref_uri = 'https://example.com/vulnerabilities/CVE-2023-0017'
    ref_type = 'web'
    ref = VulnerabilityReference(
        vuln_id=vuln.vuln_id, ref_type=ref_type, ref_uri=ref_uri)
    db.session.add(ref)
    db.session.commit()

    with app.test_request_context('/'):
        json_ld = ref.to_json_ld()
        assert json_ld['type'] == 'Reference'
        assert json_ld['referenceType'] == ref_type
        expected_id = f'https://{app.config["SERVER_NAME"]}/vuln/CVE-2023-0017#ref/{ref.vuln_ref_id}'
        assert json_ld['id'] == expected_id
        assert json_ld['rel'] == ref_uri


def test_package_create(db):
    pkg = Package(package_name="testpkg")
    db.session.add(pkg)
    db.session.commit()

    retrieved_pkg = Package.query.filter_by(package_name="testpkg").first()
    assert retrieved_pkg is not None
    assert repr(retrieved_pkg) == "<Package testpkg>"


def test_package_version_create(db):
    pkg = Package.query.filter_by(package_name="testpkg").first()
    if not pkg:
        pkg = Package(package_name="testpkg")
        db.session.add(pkg)
        db.session.commit()

    pkgver = PackageVersion(version="1.0.0", repo="main", package=pkg)
    db.session.add(pkgver)
    db.session.commit()

    retrieved_pkgver = PackageVersion.query.filter_by(version="1.0.0").first()
    assert retrieved_pkgver is not None
    assert repr(retrieved_pkgver) == "<PackageVersion testpkg-1.0.0>"
    assert retrieved_pkgver.repo == "main"
