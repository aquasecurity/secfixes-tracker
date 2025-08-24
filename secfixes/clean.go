package secfixes

import (
	"fmt"

	"gorm.io/gorm"
)

func CleanupRepo(
	repo string,
	dryRun bool,
	db *gorm.DB,
) error {
	tx := db.Begin()
	var packageVersions []PackageVersion
	tx.Where(&PackageVersion{
		Repo: repo,
	}).Find(&packageVersions)

	var vulnerabilityStates []VulnerabilityState
	tx.InnerJoins(
		"JOIN package_version pv on vulnerability_state.package_version_id = pv.package_version_id AND pv.repo = ?", repo,
	).Find(&vulnerabilityStates)

	fmt.Printf("Found %d package versions\n", len(packageVersions))
	fmt.Printf("Found %d vulnerability states\n", len(vulnerabilityStates))

	if !dryRun {
		fmt.Printf("Deleting records for %s\n", repo)
		tx.Delete(&vulnerabilityStates)
		tx.Delete(&packageVersions)
	}
	tx.Commit()
	if tx.Error != nil {
		return fmt.Errorf("could not delete records: %w", tx.Error)
	}
	return nil
}
