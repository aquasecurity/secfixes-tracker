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

    def to_nvd_severity(self):
        if self.cvss3_score > 8.0:
            return 'high'
        if self.cvss3_score > 4.0:
            return 'medium'
        return 'low'

    @classmethod
    def find_or_create(cls, cve_id: str):
        vuln = cls.query.filter_by(cve_id=cve_id).first()

        if not vuln:
            vuln = cls()
            vuln.cve_id = cve_id

        return vuln


class Package(db.Model):
    package_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_name = db.Column(db.Text)

    @classmethod
    def find_or_create(cls, package_name: str):
        pkg = cls.query.filter_by(package_name=package_name).first()

        if not pkg:
            pkg = cls()
            pkg.package_name = package_name

        return pkg


class PackageVersion(db.Model):
    package_version_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    version = db.Column(db.String(80))
    package = db.relationship('Package', backref='versions')
    repo = db.Column(db.String(80))

    @classmethod
    def find_or_create(cls, package: Package, version: str, repo: str):
        pkgver = cls.query.filter_by(package_id=package.package_id, version=version, repo=repo).first()

        if not pkgver:
            pkgver = cls()
            pkgver.package_id = package.package_id
            pkgver.version = version
            pkgver.repo = repo

        return pkgver


class VulnerabilityState(db.Model):
    vuln_state_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    package_version_id = db.Column(db.Integer, db.ForeignKey('package_version.package_version_id'), nullable=False, index=True)
    fixed = db.Column(db.Boolean)
    vuln = db.relationship('Vulnerability', backref='states')
    package_version = db.relationship('PackageVersion', backref='states')

    @classmethod
    def find_or_create(cls, package_version: PackageVersion, vuln: Vulnerability):
        state = cls.query.filter_by(package_version_id=package_version.package_version_id,
                                    vuln_id=vuln.vuln_id).first()

        if not state:
            state = cls()
            state.package_version_id = package_version.package_version_id
            state.vuln_id = vuln.vuln_id

        return state


class CPEMatch(db.Model):
    cpe_match_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    maximum_version = db.Column(db.String(80))
    vuln = db.relationship('Vulnerability', backref='cpe_matches')
    package = db.relationship('Package', backref='cpe_matches')

    @classmethod
    def find_or_create(cls, package: Package, vuln: Vulnerability, maximum_version: str):
        match = cls.query.filter_by(package_id=package.package_id, vuln_id=vuln.vuln_id).first()

        if not match:
            match = cls()
            match.package_id = package.package_id
            match.vuln_id = vuln.vuln_id
            match.maximum_version = maximum_version

        return match