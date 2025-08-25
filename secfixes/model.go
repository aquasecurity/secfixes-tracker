package secfixes

type Vulnerability struct {
	CveID                  string `gorm:"type:varchar(80);index:ix_vulnerability_cve_id"`
	Description            string
	Cvss3Vector            string                   `gorm:"type:varchar(80)"`
	CPEMatches             []CPEMatch               `gorm:"foreignKey:vuln_id"`
	VulnerabilityReference []VulnerabilityReference `gorm:"foreignKey:vuln_id"`
	VulnerabilityStates    []VulnerabilityState     `gorm:"foreignKey:vuln_id"`
	VulnID                 int                      `gorm:"primaryKey;not null;index:ix_vulnerability_vuln_id"`
	Cvss3Score             float64                  `gorm:"type:numeric"`
}

type Package struct {
	PackageName     string           `gorm:"index:ix_package_"`
	CPEMatches      []CPEMatch       `gorm:"foreignKey:vuln_id"`
	PackageVersions []PackageVersion `gorm:"foreignKey:package_id"`
	PackageID       int              `gorm:"primaryKey;not null;index:ix_package_package_id"`
}

type VulnerabilityReference struct {
	RefType   string `gorm:"type:varchar(80)"`
	RefUri    string `gorm:"index:ix_vulnerability_reference_vuln_ref_uri"`
	VulnRefID int    `gorm:"primaryKey;not null;index:ix_vulnerability_reference_vuln_ref_id"`
	VulnID    int    `gorm:"not null;ix_vulnerability_reference_vuln_id"`
}

type PackageVersion struct {
	Version             string               `gorm:"type:varchar(80)"`
	Repo                string               `gorm:"type:varchar(80);index:ix_package_version_repo"`
	Maintainer          string               `gorm:"index:ix_package_version_maintainer"`
	VulnerabilityStates []VulnerabilityState `gorm:"foreignKey:vuln_id"`
	Package             Package
	PackageVersionID    int  `gorm:"primaryKey;not null;index:ix_package_version_package_version_id"`
	PackageID           int  `gorm:"not null;index:ix_package_version_package_id"`
	Published           bool `gorm:"type:boolean;index:ix_package_version_published;check:published IN (0, 1)"`
}

type CPEMatch struct {
	MinimumVersion   *string `gorm:"type:varchar(80)"`
	MaximumVersion   *string `gorm:"type:varchar(80)"`
	MinimumVersionOP string  `gorm:"type:varchar(5)"`
	MaximumVersionOP string  `gorm:"type:varchar(5)"`
	CpeUri           string
	CpeMatchID       int  `gorm:"primaryKey;not null;index:ix_cpe_match_cpe_match_id"`
	VulnID           int  `gorm:"not null;index:ix_cpe_match_vuln_id"`
	PackageID        int  `gorm:"not null;index:ix_cpe_match_package_id"`
	Vulnerable       bool `gorm:"type:boolean;check:vulnerable IN (0, 1)"`
}

type VulnerabilityState struct {
	Vulnerability    Vulnerability `gorm:"foreignKey:vuln_id;references:vuln_id"`
	PackageVersion   PackageVersion
	VulnStateID      int `gorm:"primaryKey;not null;index:ix_vulnerability_state_vuln_state_id"`
	VulnID           int `gorm:"not null;index:ix_vulnerability_state_vuln_id"`
	PackageVersionID int `gorm:"index:ix_vulnerability_state_package_version_id"`
	Fixed            int `gorm:"check:fixed IN (0, 1)"`
}
