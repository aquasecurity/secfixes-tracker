from . import app, db
from .version import APKVersion


@app.cli.command('init-db', help='Initializes the database.')
def init_db():
    db.create_all()


class Vulnerability(db.Model):
    vuln_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = db.Column(db.String(80), index=True)
    description = db.Column(db.Text)
    cvss3_score = db.Column(db.Numeric)
    cvss3_vector = db.Column(db.String(80))

    def __repr__(self):
        return f'<Vulnerability {self.cve_id}>'

    def to_nvd_severity(self):
        if not self.cvss3_score:
            return 'unknown'
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


class VulnerabilityReference(db.Model):
    vuln_ref_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    vuln = db.relationship('Vulnerability', backref='references')
    ref_type = db.Column(db.String(80))
    ref_uri = db.Column(db.Text, index=True)

    def __repr__(self):
        return f'<VulnerabilityReference {self.ref_uri} ({self.ref_type}) for {self.vuln}>'

    @classmethod
    def find_or_create(cls, vuln: Vulnerability, ref_type: str, ref_uri: str):
        ref = cls.query.filter_by(vuln_id=vuln.vuln_id, ref_uri=ref_uri).first()

        if not ref:
            ref = cls()
            ref.vuln_id = vuln.vuln_id
            ref.ref_type = ref_type
            ref.ref_uri = ref_uri

        return ref


class Package(db.Model):
    package_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_name = db.Column(db.Text)

    def __repr__(self):
        return f'<Package {self.package_name}>'

    @classmethod
    def find_or_create(cls, package_name: str):
        pkg = cls.query.filter_by(package_name=package_name).first()

        if not pkg:
            pkg = cls()
            pkg.package_name = package_name

        return pkg

    def published_versions(self):
        return [pkgver for pkgver in self.versions if pkgver.published]

    def resolved_vulns(self):
        return [state.vuln for ver in self.versions for state in ver.states if state.fixed]

    def unresolved_vulns(self):
        return [state.vuln for ver in self.versions for state in ver.states if not state.fixed]


class PackageVersion(db.Model):
    package_version_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    version = db.Column(db.String(80))
    package = db.relationship('Package', backref='versions')
    repo = db.Column(db.String(80), index=True)
    published = db.Column(db.Boolean, index=True)

    def __repr__(self):
        return f'<PackageVersion {self.package.package_name}-{self.version}>'

    @classmethod
    def find_or_create(cls, package: Package, version: str, repo: str):
        pkgver = cls.query.filter_by(package_id=package.package_id, version=version, repo=repo).first()

        if not pkgver:
            pkgver = cls()
            pkgver.package_id = package.package_id
            pkgver.version = version
            pkgver.repo = repo

        return pkgver

    def is_vulnerable(self):
        return False in [state.fixed for state in self.states]

    def vulnerabilities(self):
        return [state.vuln for state in self.states if not state.fixed]


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
    vulnerable = db.Column(db.Boolean)
    vuln = db.relationship('Vulnerability', backref='cpe_matches')
    package = db.relationship('Package', backref='cpe_matches')

    def __repr__(self):
        ver = self.maximum_version if self.maximum_version else '*'
        return f'<CPEMatch cpe:2.3:*:{self.package.package_name}:{ver}:*:*:*:*:*:*:*:*:*>'

    @classmethod
    def find_or_create(cls, package: Package, vuln: Vulnerability, maximum_version: str, vulnerable: bool):
        match = cls.query.filter_by(package_id=package.package_id, vuln_id=vuln.vuln_id).first()

        if not match:
            match = cls()
            match.package_id = package.package_id
            match.vuln_id = vuln.vuln_id
            match.maximum_version = maximum_version
            match.vulnerable = vulnerable

        return match

    def matches_version(self, package_version: PackageVersion) -> bool:
        """
        This returns whether a CPEMatch matches a given PackageVersion.
        This does not mean that the package itself is necessarily vulnerable.
        """
        if not self.maximum_version:
            return True

        pv = APKVersion(package_version.version)
        mv = APKVersion(self.maximum_version)

        return pv == mv