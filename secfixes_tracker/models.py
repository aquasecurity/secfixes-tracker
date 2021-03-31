from . import app, db


@app.cli.command('init-db', help='Initializes the database.')
def init_db():
    db.create_all()


class Vulnerability(db.Model):
    vuln_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = db.Column(db.String(80), index=True)
    description = db.Column(db.Text)
    cvss3_score = db.Column(db.Numeric)
    cvss3_vector = db.Column(db.String(80))


class Package(db.Model):
    package_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_name = db.Column(db.Text)


class PackageVersion(db.Model):
    package_version_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    version = db.Column(db.String(80))
    package = db.relationship('Package', backref='versions')


class VulnerabilityState(db.Model):
    vuln_state_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    package_version_id = db.Column(db.Integer, db.ForeignKey('package_version.package_version_id'), nullable=False, index=True)
    fixed = db.Column(db.Boolean)
    vuln = db.relationship('Vulnerability', backref='states')
    package_version = db.relationship('PackageVersion', backref='states')