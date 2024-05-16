package secfixes

type Vulnerability struct {
	CveID       string `gorm:"index"`
	Description string
	Cvss3Vector string
	CPEMatches  []CPEMatch `gorm:"foreignKey:vuln_id"`
	VulnID      int        `gorm:"primaryKey"`
	Cvss3Score  float64
}

type Package struct {
	PackageName string     `gorm:"index"`
	CPEMatches  []CPEMatch `gorm:"foreignKey:vuln_id"`
	PackageID   int        `gorm:"primaryKey"`
}

// type VulnerabilityReference struct {
// 	VulnRefID int
// 	VulnID    int
// 	RefType   string
// 	RefUrl    string
// }

// type PackageVersion struct {
// 	PackageVersionID int
// 	PackageID        int
// 	Version          string
// 	Repo             string
// 	Published        bool
// 	Maintainer       string
// }

type CPEMatch struct {
	MinimumVersion   *string
	MaximumVersion   *string
	MinimumVersionOP string
	MaximumVersionOP string
	CpeUri           string
	CpeMatchID       int `gorm:"primaryKey"`
	VulnID           int
	PackageID        int
	Vulnerable       bool
}

// type VulnerabilityState struct {
// 	VulnStateID      int
// 	VulnID           int
// 	PackageVersionID int
// 	Fixed            int
// }
