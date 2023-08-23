import pytest


def test_index_route_html(app):
    """
    GIVEN a Flask application
    WHEN the '/' route is requested (GET) with Accept: text/html
    THEN check that the response is valid
    """
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}
    with app.test_client() as client:
        res = client.get('/', headers={"Accept": "text/html"})
        assert res.status_code == 200
        assert b'<a href="/branch/edge-main">Potentially vulnerable packages in edge-main</a>' in res.data


@pytest.mark.parametrize('accept', ['application/json', 'application/ld+json'])
def test_index_route_json(app, accept):
    """
    GIVEN a Flask application
    WHEN the '/' route is requested (GET) with Accept: application/json
    THEN check that the response is valid json
    """
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}
    with app.test_client() as client:
        res = client.get('/', headers={"Accept": accept})
        assert res.status_code == 200
        assert res.content_type == "application/json"
        assert res.json['edge-main'] == {
            'issuesByMaintainer': 'https://localhost/branch/edge-main/maintainer-issues',
            'orphanedPackages': 'https://localhost/branch/edge-main/orphaned',
            'potentiallyOrphanedVulnerablePackages': 'https://localhost/branch/edge-main/vuln-orphaned',
            'potentiallyVulnerablePackages': 'https://localhost/branch/edge-main'}


def test_branch_route_html(app):
    """
    GIVEN a Flask application
    WHEN the '/branch/edge-main' route is requests (GET) with accept txt/html
    THEN check that response is valid html
    """
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}
    with app.test_client() as client:
        res = client.get('/branch/edge-main', headers={"Accept": "text/html"})
        assert res.status_code == 200
        assert b'<h1>Potentially vulnerable packages in edge-main</h1>' in res.data


@pytest.mark.parametrize('accept', ['application/json', 'application/ld+json'])
def test_branch_route_json(app, accept):
    """
    GIVEN a Flask application
    WHEN the '/branch/edge-main' route is requested (GET) with Accept: application/json or application/ld+json
    THEN check that the response is valid json
    """
    app.config['SECFIXES_REPOSITORIES'] = {"edge-main": "https://localhost"}

    with app.test_client() as client:
        res = client.get('/branch/edge-main', headers={"Accept": accept})
        assert res.status_code == 200
        assert res.content_type == "application/json"

        assert 'id' in res.json
        assert res.json['id'] == 'https://localhost/branch/edge-main'
