from . import app, db
from .version import APKVersion


from flask import request


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

    @property
    def json_ld_id(self):
        return f'https://{request.host}/vuln/{self.cve_id}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'type': 'Vulnerability',
            'id': self.json_ld_id,
            'description': self.description,
            'cvss3': {
                 'score': float(self.cvss3_score),
                 'vector': self.cvss3_vector,
            },
            'ref': [ref.to_json_ld() for ref in self.references],
            'state': [state.to_json_ld() for state in self.states],
            'cpeMatch': [cpe_match.to_json_ld() for cpe_match in self.cpe_matches],
        }

    @property
    def published_states(self):
        return [state for state in self.states if state.package_version.published]


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

    @property
    def json_ld_id(self):
        return f'{self.vuln.json_ld_id}#ref/{self.vuln_ref_id}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'type': 'Reference',
            'referenceType': self.ref_type,
            'id': self.json_ld_id,
            'rel': self.ref_uri,
        }


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
        return list({state.vuln for ver in self.versions for state in ver.states if state.fixed})

    def unresolved_vulns(self):
        return list({state.vuln for ver in self.versions for state in ver.states if not state.fixed and ver.published})

    @property
    def excluded(self):
        return self.package_name in app.config.get('PACKAGE_EXCLUSIONS', [])

    @property
    def json_ld_id(self):
        return f'https://{request.host}/srcpkg/{self.package_name}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': self.json_ld_id,
            'type': 'Package',
            'packageVersion': [pkgver.json_ld_id for pkgver in self.versions],
            'cpeMatch': [match.to_json_ld() for match in self.cpe_matches],
        }


class PackageVersion(db.Model):
    package_version_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    version = db.Column(db.String(80))
    package = db.relationship('Package', backref='versions')
    repo = db.Column(db.String(80), index=True)
    published = db.Column(db.Boolean, index=True)
    maintainer = db.Column(db.Text, index=True)

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

    @property
    def json_ld_id(self):
        return f'{self.package.json_ld_id}/{self.version}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': self.json_ld_id,
            'type': 'PackageVersion',
            'package': self.package.to_json_ld(),
            'published': self.published,
            'repo': self.repo,
            'maintainer': self.maintainer,
            'state': [state.to_json_ld() for state in self.states],
        }


class VulnerabilityState(db.Model):
    vuln_state_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    package_version_id = db.Column(db.Integer, db.ForeignKey('package_version.package_version_id'), nullable=False, index=True)
    fixed = db.Column(db.Boolean)
    vuln = db.relationship('Vulnerability', backref='states')
    package_version = db.relationship('PackageVersion', backref='states')

    def __repr__(self):
        return f'<VulnerabilityState {self.package_version} fixed={self.fixed}>'

    @classmethod
    def find_or_create(cls, package_version: PackageVersion, vuln: Vulnerability):
        state = cls.query.filter_by(package_version_id=package_version.package_version_id,
                                    vuln_id=vuln.vuln_id).first()

        if not state:
            state = cls()
            state.package_version_id = package_version.package_version_id
            state.vuln_id = vuln.vuln_id

        return state

    @property
    def json_ld_id(self):
        return f'{self.vuln.json_ld_id}#state/{self.vuln_state_id}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': self.json_ld_id,
            'type': 'VulnerabilityState',
            'vuln': self.vuln.json_ld_id,
            'fixed': self.fixed,
            'packageVersion': self.package_version.json_ld_id,
        }


class CPEMatch(db.Model):
    cpe_match_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.package_id'), nullable=False, index=True)
    minimum_version = db.Column(db.String(80))
    minimum_version_op = db.Column(db.String(5))
    maximum_version = db.Column(db.String(80))
    maximum_version_op = db.Column(db.String(5))
    vulnerable = db.Column(db.Boolean)
    cpe_uri = db.Column(db.Text)
    vuln = db.relationship('Vulnerability', backref='cpe_matches')
    package = db.relationship('Package', backref='cpe_matches')

    def __repr__(self):
        return f'<CPEMatch {self.package.package_name} ({self.minimum_version_op} {self.minimum_version}) ({self.maximum_version_op} {self.maximum_version})>'

    @classmethod
    def find_or_create(cls, package: Package, vuln: Vulnerability, minimum_version: str, minimum_version_op: str,
                       maximum_version: str, maximum_version_op: str, vulnerable: bool, cpe_uri: str):
        match = cls.query.filter_by(package_id=package.package_id, vuln_id=vuln.vuln_id,
                                    minimum_version=minimum_version, maximum_version=maximum_version).first()

        if not match:
            match = cls()
            match.package_id = package.package_id
            match.vuln_id = vuln.vuln_id
            match.minimum_version = minimum_version
            match.maximum_version = maximum_version
            match.minimum_version_op = minimum_version_op
            match.maximum_version_op = maximum_version_op
            match.vulnerable = vulnerable
            match.cpe_uri = cpe_uri

        return match

    def matches_version(self, package_version: PackageVersion) -> bool:
        """
        This returns whether a CPEMatch matches a given PackageVersion.
        This does not mean that the package itself is necessarily vulnerable.
        """
        # An excluded package will never match a CPE.
        if package_version.package.excluded:
            return False

        ver = package_version.version.split('-r')[0]
        pv = APKVersion(ver)

        # Verify the minimum version is met, if there is one.
        if self.minimum_version:
            minv = APKVersion(self.minimum_version)

            if self.minimum_version_op == '>=' and pv < minv:
                return False
            elif self.minimum_version_op == '>' and pv <= minv:
                return False

        # If the maximum version is unbounded, assume we're vulnerable.
        if not self.maximum_version:
            return True

        # Otherwise, compare.
        maxv = APKVersion(self.maximum_version)

        if self.maximum_version_op == '<=' and pv <= maxv:
            return True
        elif self.maximum_version_op == '<' and pv < maxv:
            return True
        elif self.maximum_version_op == '==' and pv == maxv:
            return True

        return False

    @property
    def json_ld_id(self):
        return f'{self.vuln.json_ld_id}#cpeMatch/{self.cpe_match_id}'

    def to_json_ld(self):
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'id': self.json_ld_id,
            'type': 'CPEMatch',
            'vuln': self.vuln.json_ld_id,
            'package': self.package.json_ld_id,
            'minimumVersion': self.minimum_version,
            'minimumVersionOp': self.minimum_version_op,
            'maximumVersion': self.maximum_version,
            'maximumVersionOp': self.maximum_version_op,
            'cpeUri': self.cpe_uri,
        }