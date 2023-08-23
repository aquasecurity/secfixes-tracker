
import json
import gzip
from unittest.mock import patch
from secfixes_tracker.models import Vulnerability


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
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {
                            "baseScore": 5.0,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
                        }
                    }
                }
            }
        ]
    }

    compressed_data = gzip.compress(json.dumps(sample_data).encode())

    with patch('requests.get') as mock_get:
        mock_get.return_value.content = compressed_data

        result = runner.invoke(args=["import-nvd", "sample_name"])

    # Ensure the command completed without errors
    assert result.exit_code == 0

    # You can then check that the right entities were created in the database
    # Example:
    vuln = Vulnerability.query.filter_by(cve_id="sample_cve_id").first()
    assert vuln is not None
    assert vuln.description == "Sample CVE Description"
