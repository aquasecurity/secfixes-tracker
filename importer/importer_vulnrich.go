package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	o "github.com/moznion/go-optional"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/importer/vulnrich"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
	"gorm.io/gorm"
)

func VulnrichtFeed(
	db *gorm.DB,
	config secfixes.Config,
	period time.Duration,
) error {
	slog.Info("Fetching vulnrichment repository")
	repo, err := vulnrich.GetRepo("https://github.com/cisagov/vulnrichment.git", "vulnrichment.git")
	if err != nil {
		return err
	}

	err = vulnrich.UpdateRepo(repo)
	if err != nil {
		return fmt.Errorf("could not update vulnrichment repo: %w", err)
	}

	cveFiles, err := vulnrich.GetCVEFiles(repo)
	if err != nil {
		return fmt.Errorf("could not get files from repo: %w", err)
	}

	records := vulnrich.Records{}
	for _, entryReader := range cveFiles {
		entry := vulnrich.Record{}
		data, err := io.ReadAll(entryReader.Content)
		if err != nil {
			return err
		}
		entryReader.Content.Close()

		err = json.Unmarshal(data, &entry)
		if err != nil {
			slog.Error("could not unmarshal vulnrich record", "filename", entryReader.Name, "err", err)
			continue
		}

		records = append(records, entry)
	}
	for _, record := range records.Filter(func(r vulnrich.Record) bool {
		container := OptionalFirst(r.Containers.Adp).TakeOr(r.Containers.Cna)
		return container.ProviderMetadata.DateUpdated.After(time.Now().Add(-period))
	}) {
		container := OptionalFirst(record.Containers.Adp).TakeOr(record.Containers.Cna)
		slog.Info("CVE record", "cve", record.CveMetadata.CveID, "updated", container.ProviderMetadata.DateUpdated)
		err := ProcessVulnrichRecord(db, config, record)
		if err != nil {
			slog.Error("could not process vulnricht record", "cve", record.CveMetadata.CveID, "err", err)
		}
	}

	return nil
}

func ProcessVulnrichRecord(
	db *gorm.DB,
	config secfixes.Config,
	record vulnrich.Record,
) error {
	rewriters := make([]compiledRewriter, 0, len(config.Rewriters))
	for i, rewriter := range config.Rewriters {
		cr, err := NewCompiledRewriter(rewriter)
		if err != nil {
			return fmt.Errorf("could not parse rewrite rule %d, %w", i+1, err)
		}
		rewriters = append(rewriters, cr)
	}

	cna := record.Containers.Cna
	adp := OptionalFirst(record.Containers.Adp)

	cveDescription := o.None[vulnrich.CveDescriptions]()

	if record.CveMetadata.State == vulnrich.CveStateREJECTED {
		cveDescription = o.Some(record.Containers.Cna.RejectedReasons)
	}

	cveDescription = cveDescription.
		Or(OptionalNonEmpty(cna.Descriptions)).
		Or(o.FlatMap(adp, func(v vulnrich.CveContainer) o.Option[vulnrich.CveDescriptions] {
			return OptionalNonEmpty(v.Descriptions)
		}))

	description := o.
		FlatMap(cveDescription, func(v vulnrich.CveDescriptions) o.Option[string] {
			cveDescription := v.ForLang("en").Or(
				v.ForLang("en-US"),
			)

			return o.FlatMap(cveDescription, func(v vulnrich.CveDescription) o.Option[string] {
				return o.Some(v.Value)
			})
		}).
		Or(cna.Title)

	if description.IsNone() {
		slog.Warn("No descriptions found", "cve", record.CveMetadata.CveID)
		return nil
	}

	var metric o.Option[vulnrich.Metric]

	// Default to metrics from CNA
	metric = OptionalFirst(cna.Metrics)

	// If metrics from ADP are available and no metrics from CNA are available,
	// use that.
	metric = metric.Or(
		o.FlatMap(
			OptionalFirst(record.Containers.Adp),
			func(v vulnrich.CveContainer) o.Option[vulnrich.Metric] {
				return OptionalFirst(v.Metrics)
			},
		),
	)

	// Find the highest available cvss version metric on the found metric
	cvssMetric := o.FlatMap(
		metric,
		func(v vulnrich.Metric) o.Option[vulnrich.CvssMetric] {
			return o.None[vulnrich.CvssMetric]().
				Or(v.CvssV40).
				Or(v.CvssV31).
				Or(v.CvssV30).
				Or(v.CvssV20)
		},
	)

	vuln := secfixes.Vulnerability{}
	description.IfSome(func(v string) {
		vuln.Description = v
	})

	cvssMetric.IfSome(func(v vulnrich.CvssMetric) {
		vuln.Cvss3Score, _ = v.BaseScore.Float64()
		vuln.Cvss3Vector = v.VectorString
	})

	result := db.
		Where(secfixes.Vulnerability{CveID: record.CveMetadata.CveID}).
		Assign(vuln).
		FirstOrCreate(&vuln)
	if result.Error != nil {
		return fmt.Errorf("could not create or update cve %s: %w", record.CveMetadata.CveID, result.Error)
	}

	cpeMatchIDsByPackage := map[int][]int{}
	for _, affected := range cna.Affected {
		cpeMatchIDsByPackageForAffected, err := ProcessCveAffected(db, config, rewriters, cna, vuln, affected)
		if err != nil {
			slog.Error("could not process cna.Affected", "err", err)
			continue
		}

		for packageID, matchIDs := range cpeMatchIDsByPackageForAffected {
			cpeMatchIDsByPackage[packageID] = append(cpeMatchIDsByPackage[packageID], matchIDs...)
		}
	}

	adp.IfSome(func(adp vulnrich.CveContainer) {
		for _, affected := range adp.Affected {
			cpeMatchIDsByPackageForAffected, err := ProcessCveAffected(db, config, rewriters, adp, vuln, affected)
			if err != nil {
				slog.Error("could not process adp.Affected", "err", err)
				continue
			}

			for packageID, matchIDs := range cpeMatchIDsByPackageForAffected {
				cpeMatchIDsByPackage[packageID] = append(cpeMatchIDsByPackage[packageID], matchIDs...)
			}
		}
	})

	refs := OptionalNonEmpty(cna.References).
		Or(o.Map(adp, func(v vulnrich.CveContainer) []vulnrich.Reference { return v.References })).
		TakeOr([]vulnrich.Reference{})

	for _, ref := range refs {
		err := ProcessCveRef(db, config, vuln, ref)
		if err != nil {
			slog.Error("could not process ref", "cve", vuln.CveID, "url", ref.URL, "err", err)
		}
	}

	packageIDs := []int{}
	for packageID, cpeMatchIDs := range cpeMatchIDsByPackage {
		packageIDs = append(packageIDs, packageID)
		result := db.Exec(
			`DELETE FROM cpe_match where vuln_id = ? and package_id = ? and cpe_match_id NOT IN ?`,
			vuln.VulnID,
			packageID,
			cpeMatchIDs,
		)
		if result.Error != nil {
			slog.Error(
				"could not clean up matches for package",
				"vuln_id", vuln.VulnID,
				"cve", vuln.CveID,
				"package_id", packageID,
				"err", result.Error,
			)
			continue
		}
		slog.Debug(
			"cleaning up left over matches for package",
			"vuln_id", vuln.VulnID,
			"cve", vuln.CveID,
			"package_id", packageID,
			"deleted", result.RowsAffected,
		)
	}

	slog.Debug("cleaning up orphaned CPE matches", "cve", vuln.CveID)
	if len(packageIDs) > 0 {
		result = db.Exec(
			`DELETE FROM cpe_match where vuln_id = ? AND package_id not in ?`,
			vuln.VulnID,
			packageIDs,
		)
	} else {
		result = db.Exec(
			`DELETE FROM cpe_match where vuln_id = ?`,
			vuln.VulnID,
		)
	}

	if result.Error != nil {
		slog.Error("could not delete orphaned cpe matches", "err", result.Error)
		return nil
	}
	slog.Debug("finished", "deleted", result.RowsAffected)

	return nil
}

func ProcessCveAffected(
	db *gorm.DB,
	config secfixes.Config,
	rewriters []compiledRewriter,
	cveContainer vulnrich.CveContainer,
	vuln secfixes.Vulnerability,
	affected vulnrich.Affected,
) (cpeMatchIDsByPackage map[int][]int, err error) {
	cpe := o.FlatMap(
		OptionalFirst(affected.CPEs), func(v string) o.Option[CPE23Uri] {
			cpe, _ := NewCPEUri(v)
			return o.Some(cpe)
		}).
		TakeOr(CPE23Uri{Vendor: affected.Vendor, Product: affected.Product})

	for _, rewriter := range rewriters {
		cpe = rewriter.Rewrite(cpe)
	}

	cpeMatchIDsByPackage = map[int][]int{}
	for _, version := range affected.Versions {
		cpeMatchId, err := ProcessCveAffectedVersion(db, config, rewriters, cveContainer, vuln, affected, version, cpe)
		if err != nil {
			return nil, err
		}
		cpeMatchId.IfSome(func(v secfixes.CPEMatch) {
			cpeMatchIDsByPackage[v.PackageID] = append(cpeMatchIDsByPackage[v.PackageID], v.CpeMatchID)
		})
	}

	return cpeMatchIDsByPackage, nil
}

func ProcessCveAffectedVersion(
	db *gorm.DB,
	config secfixes.Config,
	rewriters []compiledRewriter,
	cveContainer vulnrich.CveContainer,
	vuln secfixes.Vulnerability,
	affected vulnrich.Affected,
	version vulnrich.Version,
	cpe CPE23Uri,
) (cpeMatchId o.Option[secfixes.CPEMatch], err error) {
	sourcePkgname := cpe.Product

	minVersion := strings.TrimSpace(version.Version.String())
	maxVersion := o.None[string]()
	minVersionOp := "=="
	maxVersionOp := "=="

	vulnerable := o.MapOr(
		version.Status.Or(affected.DefaultStatus),
		false,
		func(v vulnrich.AffectedStatus) bool {
			return v == vulnrich.AffectedStatusAffected
		})

	var validVersion bool
	switch {
	case cveContainer.ProviderMetadata.ShortName == "GitHub_M" && version.LessThan.IsNone() && version.LessThanOrEqual.IsNone():
		validVersion = processVersionGithub(version, &minVersion, &maxVersion, &minVersionOp, &maxVersionOp)
	default:
		validVersion = processVersionStandard(version, &minVersion, &maxVersion, &minVersionOp, &maxVersionOp)
	}
	if !validVersion {
		return o.None[secfixes.CPEMatch](), nil
	}

	pkg := secfixes.Package{PackageName: sourcePkgname}
	result := db.
		Where(pkg).
		Assign(pkg).
		FirstOrCreate(&pkg)

	if result.Error != nil {
		slog.Error(
			"could not create or update package",
			"package", pkg.PackageName,
			"cve", vuln.CveID,
			"err", result.Error,
		)
		return o.None[secfixes.CPEMatch](), nil
	}

	cpeMatch := secfixes.CPEMatch{
		VulnID:           vuln.VulnID,
		PackageID:        pkg.PackageID,
		Vulnerable:       vulnerable,
		MinimumVersion:   &minVersion,
		MaximumVersion:   maxVersion.UnwrapAsPtr(),
		MinimumVersionOP: minVersionOp,
		MaximumVersionOP: maxVersionOp,
	}

	slog.Debug(
		"cpematch",
		"cve", vuln.CveID,
		"package", pkg.PackageName,
		"vulnerable", vulnerable,
		"minimumVersion", minVersion,
		"minVersionOp", minVersionOp,
		"maxVersion", maxVersion.TakeOr(""),
		"maxVersionOp", maxVersionOp,
	)

	result = db.
		Where(secfixes.CPEMatch{
			VulnID:           vuln.VulnID,
			PackageID:        pkg.PackageID,
			CpeUri:           cpe.Uri,
			MinimumVersion:   &minVersion,
			MaximumVersion:   maxVersion.UnwrapAsPtr(),
			MinimumVersionOP: minVersionOp,
			MaximumVersionOP: maxVersionOp,
		}).
		Assign(cpeMatch).
		FirstOrCreate(&cpeMatch)
	if result.Error != nil {
		slog.Error(
			"coiuld not create or update cpematch",
			"package", pkg.PackageName,
			"cve", vuln.CveID,
			"err", result.Error,
		)
		return o.None[secfixes.CPEMatch](), nil
	}
	return o.Some(cpeMatch), nil
}

func processVersionStandard(
	version vulnrich.Version,
	minVersion *string,
	maxVersion *o.Option[string],
	minVersionOp, maxVersionOp *string,
) (valid bool) {
	version.LessThan.IfSome(func(v string) {
		*minVersionOp = ">="
		*maxVersionOp = "<"
		*maxVersion = o.Some(v)
	})

	version.LessThanOrEqual.IfSome(func(v string) {
		*minVersionOp = ">="
		*maxVersionOp = "<="
		*maxVersion = o.Some(v)
	})

	if (*maxVersionOp)[0] == '<' && (*minVersion == "-" || *minVersion == "*") {
		*minVersion = "0"
	}

	if (*maxVersionOp)[0] == '<' && *minVersion == maxVersion.TakeOr("") {
		*minVersion = "0"
	}

	if *minVersionOp == "==" && *maxVersionOp == "==" {
		*maxVersion = o.Some(*minVersion)
	}

	if *minVersion == "-" || *minVersion == "*" {
		// Cannot say anything useful about this version
		return false
	}

	return true
}

func processVersionGithub(
	version vulnrich.Version,
	minVersion *string,
	maxVersion *o.Option[string],
	minVersionOp, maxVersionOp *string,
) (valid bool) {
	firstLimit, secondLimit, hasLowerBound := strings.Cut(version.Version.String(), ", ")

	firstLimitOp, firstLimitVer, _ := strings.Cut(firstLimit, " ")

	if hasLowerBound {
		secondLimitOp, secondLimitVer, _ := strings.Cut(secondLimit, " ")
		*minVersion = firstLimitVer
		*minVersionOp = firstLimitOp
		*maxVersion = o.Some(secondLimitVer)
		*maxVersionOp = secondLimitOp
	} else {
		*minVersion = "0"
		*minVersionOp = ">="
		*maxVersion = o.Some(firstLimitVer)
		*maxVersionOp = firstLimitOp
	}

	return true
}

func ProcessCveRef(
	db *gorm.DB,
	config secfixes.Config,
	vuln secfixes.Vulnerability,
	ref vulnrich.Reference,
) error {
	tag := OptionalFirst(ref.Tags).
		TakeOr("")

	tag = strings.TrimPrefix(tag, "x_refsource_")

	vulnRef := secfixes.VulnerabilityReference{
		VulnID:  vuln.VulnID,
		RefUri:  ref.URL,
		RefType: tag,
	}

	db.
		Where(secfixes.VulnerabilityReference{
			VulnID: vuln.VulnID,
			RefUri: ref.URL,
		}).
		Assign(vulnRef).
		FirstOrCreate(&vulnRef)

	return db.Error
}
