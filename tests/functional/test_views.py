import pytest

content_types = ['application/json', 'application/ld+json', 'text/html']


@pytest.mark.parametrize('accept', content_types)
def test_index_route(app, client, accept):
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}

    res = client.get('/', headers={"Accept": accept})
    if accept == 'text/html':
        assert res.status_code == 200
        assert b'<a href="/branch/edge-main">Potentially vulnerable packages in edge-main</a>' in res.data

    else:
        # json
        assert res.status_code == 200
        assert res.content_type == "application/json"
        assert res.json['edge-main'] == {
            'issuesByMaintainer': 'https://localhost/branch/edge-main/maintainer-issues',
            'orphanedPackages': 'https://localhost/branch/edge-main/orphaned',
            'potentiallyOrphanedVulnerablePackages': 'https://localhost/branch/edge-main/vuln-orphaned',
            'potentiallyVulnerablePackages': 'https://localhost/branch/edge-main'}


@pytest.mark.parametrize('accept', content_types)
def test_branch_route(app, client, accept):
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}

    res = client.get('/branch/edge-main', headers={"Accept": accept})
    if accept == 'text/html':
        assert res.status_code == 200
        assert b'<h1>Potentially vulnerable packages in edge-main</h1>' in res.data

    else:
        # json
        assert res.status_code == 200
        assert res.content_type == "application/json"

        assert 'id' in res.json
        assert res.json['id'] == 'https://localhost/branch/edge-main'


@pytest.mark.parametrize('accept', content_types)
def test_branch_vuln_orphaned_route_json(app, client, accept):
    branch_name = "edge-main"  # as an example
    app.config['SECFIXES_REPOSITORIES'] = {branch_name: "https://localhost"}

    res = client.get(
        f'/branch/{branch_name}/vuln-orphaned', headers={"Accept": accept})
    if accept == 'text/html':
        assert res.status_code == 200
        assert b'<title>Potentially vulnerable orphaned packages in edge-main' in res.data

    else:
        # json
        assert res.status_code == 200
        assert res.content_type == "application/json"

        assert '@context' in res.json
        assert res.json['id'] == 'https://localhost/branch/edge-main/vuln-orphaned'
        assert res.json['items'] == []
