package importer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/moznion/go-optional"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
	"gorm.io/gorm"
)

func NVDFeed(
	db *gorm.DB,
	nvdApi *APIv2,
	config secfixes.Config,
	period time.Duration,
) error {
	rewriters := make([]compiledRewriter, 0, len(config.Rewriters))
	for i, rewriter := range config.Rewriters {
		cr, err := NewCompiledRewriter(rewriter)
		if err != nil {
			return fmt.Errorf("could not parse rewrite rule %d, %w", i+1, err)
		}
		rewriters = append(rewriters, cr)
	}
	slog.Info("Importing NVD change feed", "period", period)

	start := time.Date(2023, 7, 4, 0, 0, 0, 0, time.UTC)
	end := time.Date(2023, 7, 12, 0, 0, 0, 0, time.UTC)
	slog.Info("Requesting CVEs", "starttime", start, "endtime", end)
	resp, err := nvdApi.GetCVEs(
		PubStart(start),
		PubEnd(end),
	)
	if err != nil {
		return fmt.Errorf("could not get nvd change feed: %w", err)
	}
	slog.Info("Finished requesting CVEs", "total_results", resp.TotalResults, "results", len(resp.Vulnerabilities))

	ctx := context.Background()
	tx := db.Begin()

	if tx.Error != nil {
		return fmt.Errorf("could not start transaction: %w", err)
	}

	for _, item := range resp.Vulnerabilities {
		err := ProcessNvdCveItem(ctx, tx, rewriters, item)
		if err != nil {
			slog.Error("could not process item", "item", item.CVE.ID, "err", err)
		}
	}

	result := tx.Commit()

	return result.Error
}

func ProcessNvdCveItem(
	ctx context.Context,
	db *gorm.DB,
	rewriters []compiledRewriter,
	item Vulnerability,
) error {
	description := item.CVE.Descriptions.SelectLang("en")
	if description.IsNone() {
		return nil
	}

	slog.Info("Processing vulnerability", "cve", item.CVE.ID)

	impact := item.CVE.Metrics.CvssMetricV31.SelectByType("Primary")

	vuln := secfixes.Vulnerability{}
	description.IfSome(func(v Description) {
		vuln.Description = v.Value
	})
	impact.IfSome(func(v CvssMetricV31) {
		var err error
		vuln.Cvss3Score, err = v.CvssData.BaseScore.Float64()
		if err != nil {
			slog.Error(
				"could not convert basescore to float64",
				"cve", item.CVE.ID,
				"err", err,
			)
		}
		vuln.Cvss3Vector = v.CvssData.VectorString
	})
	result := db.
		Where(secfixes.Vulnerability{CveID: item.CVE.ID}).
		Assign(vuln).
		FirstOrCreate(&vuln)

	if result.Error != nil {
		return fmt.Errorf("could not create or update cve %s: %w", item.CVE.ID, result.Error)
	}

	ProcessNvdCveConfigurations(
		ctx,
		db,
		vuln,
		rewriters,
		item.CVE.Configurations)

	return nil
}

func ProcessNvdCveConfigurations(
	ctx context.Context,
	db *gorm.DB,
	vuln secfixes.Vulnerability,
	rewriters []compiledRewriter,
	configurations []Configuration,
) {
	for _, configuration := range configurations {
		for _, node := range configuration.Nodes {
			for _, match := range node.CPEMatch {
				cpe := match.Criteria
				for _, rewriter := range rewriters {
					cpe = rewriter.Rewrite(cpe)
				}
				sourcePkgname := cpe.Product

				sourceVersion := optional.Some(cpe.Version)
				if cpe.Version == "*" {
					sourceVersion = optional.None[string]()
				}
				maxVersion := match.VersionEndIncluding.Or(
					match.VersionEndExcluding.Or(
						sourceVersion,
					),
				)
				minVersion := match.VersionStartIncluding.Or(
					match.VersionStartExcluding,
				)
				minVersionOp := "=="
				maxVersionOp := "=="

				if match.UsesVersionRanges() {
					minVersionOp = ">="
					if match.VersionStartExcluding.IsSome() {
						minVersionOp = ">"
					}

					maxVersionOp = "<="
					if match.VersionEndExcluding.IsSome() {
						maxVersionOp = "<"
					}
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
					continue
				}

				cpeMatch := secfixes.CPEMatch{
					VulnID:           vuln.VulnID,
					PackageID:        pkg.PackageID,
					MinimumVersion:   minVersion.UnwrapAsPtr(),
					MaximumVersion:   maxVersion.UnwrapAsPtr(),
					MinimumVersionOP: minVersionOp,
					MaximumVersionOP: maxVersionOp,
					Vulnerable:       match.Vulnerable,
					CpeUri:           cpe.Uri,
				}
				result = db.
					Where(secfixes.CPEMatch{
						VulnID:    vuln.VulnID,
						PackageID: pkg.PackageID,
					}).
					Assign(cpeMatch).
					FirstOrCreate(&cpeMatch)
				if result.Error != nil {
					slog.Error(
						"could not create or update cpematch",
						"package", pkg.PackageName,
						"cve", vuln.CveID,
						"match_criteria_id", match.MatchCriteriaId,
						"err", result.Error,
					)
				}
			}
		}
	}
}
