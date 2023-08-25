import gzip
import io
import json
import requests_mock
import tarfile
import yaml

from unittest.mock import patch, mock_open
from secfixes_tracker.models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch


def test_import_nvd_command(runner):
    # Sample mock data (replace with an actual sample for your test)
    sample_data = {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "sample_cve_id"},
                    "description": {
                        "description_data": [{"value": "Sample CVE Description"}]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "refsource": "example",
                                "url": "http://example.com",
                                "tags": ["tag1", "tag2"]
                            }
                        ]
                    }
                },
                "configurations": {
                    "nodes": [
                        {
                            "cpe_match": [
                                {
                                    "cpe23Uri": "cpe:2.3:o:canonical:ubuntu_linux:12.04:*:*:*:lts:*:*:*",
                                    "vulnerable": True,
                                    "versionStartIncluding": "5.5.0",
                                    "versionEndIncluding": "5.5.43"
                                }
                            ]
                        }
                    ]
                },
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {
                            "baseScore": 5.0,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
                        }
                    }
                }
            },
            {"foo": "missing 'cve'"},
            {"cve": {"CVE_data_meta": {"foo": "missing ID"}}},
            {"cve": {"CVE_data_meta": {"ID": "missing description"}}},
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-5678"},
                    "description": {
                        "description_data": [{"value": "Sample CVE without URL"}]
                    },
                    "references": {
                        "reference_data": [
                            {
                                "refsource": "missing url",
                                "tags": ["tag1", "tag2"]
                            }
                        ]
                    }
                },
            }
        ]
    }

    compressed_data = gzip.compress(json.dumps(sample_data).encode())

    with patch('requests.get') as mock_get:
        mock_get.return_value.content = compressed_data

        result = runner.invoke(args=["import-nvd", "sample_name"])

    # Ensure the command completed without errors
    assert result.exit_code == 0

    vuln = Vulnerability.query.filter_by(cve_id="sample_cve_id").first()
    assert vuln is not None
    assert vuln.description == "Sample CVE Description"


def test_import_nvd_command_no_cve_items(runner):
    sample_data = {"foo": "bar"}
    compressed_data = gzip.compress(json.dumps(sample_data).encode())

    with patch('requests.get') as mock_get:
        mock_get.return_value.content = compressed_data
        result = runner.invoke(args=["import-nvd", "sample_name"])

    # Ensure the command completed without errors
    assert result.exit_code == 1


def test_import_secfixes_command(runner, app):
    sample_data = {
        "packages": [
            {
                "pkg": {
                    "name": "sample_package",
                    "secfixes": {
                        "1.0.0": ["CVE-1234", "CVE-5678"]
                    }
                }
            }
        ]
    }

    app.config['SECFIXES_REPOSITORIES'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }

    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = sample_data
        result = runner.invoke(args=["import-secfixes", "sample_repo"])

    assert result.exit_code == 0

    pkg = Package.query.filter_by(package_name="sample_package").first()
    assert pkg is not None

    pkgver = PackageVersion.query.filter_by(
        package=pkg, version="1.0.0").first()
    assert pkgver is not None

    vuln1 = Vulnerability.query.filter_by(cve_id="CVE-1234").first()
    assert vuln1 is not None

    vuln2 = Vulnerability.query.filter_by(cve_id="CVE-5678").first()
    assert vuln2 is not None

    state1 = VulnerabilityState.query.filter_by(
        package_version=pkgver, vuln=vuln1).first()
    assert state1 is not None
    assert state1.fixed

    state2 = VulnerabilityState.query.filter_by(
        package_version=pkgver, vuln=vuln2).first()
    assert state2 is not None
    assert state2.fixed


def test_import_secfixes_command_no_repo(runner, app):
    app.config['SECFIXES_REPOSITORIES'] = {}
    result = runner.invoke(args=["import-secfixes"])

    # Ensure error since no repositories are configured
    assert result.exit_code == 1


def test_import_secfixes_command_invalid_repo(runner, app):
    app.config['SECFIXES_REPOSITORIES'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }
    result = runner.invoke(args=["import-secfixes", "invalid_repo"])
    assert result.exit_code == 1


def test_import_rejections_command(runner, app):
    sample_data = {
        "sample_package": ["CVE-1234", "CVE-5678"]
    }
    sample_yaml = yaml.dump(sample_data)

    app.config['SECURITY_REJECTIONS'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }

    with patch('requests.get') as mock_get:
        mock_get.return_value.content = sample_yaml.encode('utf-8')
        result = runner.invoke(args=["import-rejections", "sample_repo"])

    assert result.exit_code == 0

    pkg = Package.query.filter_by(package_name="sample_package").first()
    assert pkg is not None

    pkgver = PackageVersion.query.filter_by(
        package=pkg, version="0").first()
    assert pkgver is not None

    vuln1 = Vulnerability.query.filter_by(cve_id="CVE-1234").first()
    assert vuln1 is not None

    vuln2 = Vulnerability.query.filter_by(cve_id="CVE-5678").first()
    assert vuln2 is not None

    state1 = VulnerabilityState.query.filter_by(
        package_version=pkgver, vuln=vuln1).first()
    assert state1 is not None
    assert state1.fixed

    state2 = VulnerabilityState.query.filter_by(
        package_version=pkgver, vuln=vuln2).first()
    assert state2 is not None
    assert state2.fixed


def test_import_rejections_command_invalid_yaml(runner, app):
    invalid_yaml = "sample_package: CVE-1234\ninvalid_syntax:"

    app.config['SECURITY_REJECTIONS'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }

    with patch('requests.get') as mock_get:
        mock_get.return_value.content = invalid_yaml.encode('utf-8')
        result = runner.invoke(args=["import-rejections", "sample_repo"])

    assert result.exit_code == 1
    assert "Encountered" in result.output
    assert "while parsing security rejections feed." in result.output


def test_import_rejections_command_invalid_repo(runner, app):
    app.config['SECURITY_REJECTIONS'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }

    result = runner.invoke(args=["import-rejections", "invalid_repo"])
    assert result.exit_code == 1


def create_in_memory_apkindex(data):
    """Create an in-memory tarball and return the file object."""
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        encoded_data = data.encode('utf-8')
        file = io.BytesIO(encoded_data)
        tarinfo = tarfile.TarInfo(name="APKINDEX")
        tarinfo.size = len(encoded_data)
        tar.addfile(tarinfo, fileobj=file)
    tar_stream.seek(0)
    return tar_stream


def test_import_apkindex_command(runner, app):
    # Sample mock data for the APKINDEX repository
    sample_data = """o:origin_package
P:origin_package
V:1.0
m:maintainer@example.com

o:origin_package
P:sample_package
V:1.0
m:maintainer@example.com
"""

    # Create an in-memory tarball from sample_data
    tarball = create_in_memory_apkindex(sample_data)

    # Mock APKINDEX_REPOSITORIES in app config
    app.config['APKINDEX_REPOSITORIES'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }

    # Mock requests.get to return the in-memory tarball
    with requests_mock.Mocker() as mocker:
        mocker.get('http://sample_repo_url.com', content=tarball.getvalue())

        # Call the import-apkindex command with the repo argument
        result = runner.invoke(args=["import-apkindex", "sample_repo"])

    # Ensure the command completed without errors
    assert result.exit_code == 0

    # Check that the appropriate package and package version were added to the database
    pkg = Package.query.filter_by(package_name="origin_package").first()
    assert pkg is not None

    pkgver = PackageVersion.query.filter_by(
        package=pkg, version="1.0").first()
    assert pkgver is not None
    assert pkgver.maintainer == "maintainer@example.com"
    assert pkgver.published


def test_import_apkindex_command_invalid_repo(runner, app):
    app.config['APKINDEX_REPOSITORIES'] = {
        'sample_repo': 'http://sample_repo_url.com'
    }
    result = runner.invoke(args=["import-apkindex", "invalid_repo"])
    assert result.exit_code == 1
