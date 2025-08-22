package secfixes

type Vulnerability struct {
	CveID                  string `gorm:"type:varchar(80);index:ix_vulnerability_cve_id"`
	Description            string
	Cvss3Vector            string                   `gorm:"type:varchar(80)"`
	CPEMatches             []CPEMatch               `gorm:"foreignKey:vuln_id"`
	VulnerabilityReference []VulnerabilityReference `gorm:"foreignKey:vuln_id"`
	VulnID                 int                      `gorm:"primaryKey;not null;index:ix_vulnerability_vuln_id"`
	Cvss3Score             float64                  `gorm:"type:numeric"`
}

type Package struct {
	PackageName string     `gorm:"index:ix_package_"`
	CPEMatches  []CPEMatch `gorm:"foreignKey:vuln_id"`
	PackageID   int        `gorm:"primaryKey;not null;index:ix_package_package_id"`
}

type VulnerabilityReference struct {
	RefType   string `gorm:"type:varchar(80)"`
	RefUri    string `gorm:"index:ix_vulnerability_reference_vuln_ref_uri"`
	VulnRefID int    `gorm:"primaryKey;not null;index:ix_vulnerability_reference_vuln_ref_id"`
	VulnID    int    `gorm:"not null;ix_vulnerability_reference_vuln_id"`
}

// type PackageVersion struct {
// 	PackageVersionID int
// 	PackageID        int
// 	Version          string
// 	Repo             string
// 	Published        bool
// 	Maintainer       string
// }

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

// type VulnerabilityState struct {
// 	VulnStateID      int
// 	VulnID           int
// 	PackageVersionID int
// 	Fixed            int
// }
