package main

import (
	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/importer"
)

var vulnrichtmentCmd = &cobra.Command{
	Use:   "import-vulnrich",
	Short: "Import vulnrichment secfixes",
	RunE:  runImportVulnrichment,
}

func runImportVulnrichment(cmd *cobra.Command, args []string) error {
	tx := App().DB.Begin()
	defer tx.Commit()

	return importer.VulnrichtFeed(
		tx, App().Config, App().Config.Importers.Vulnrich.LookupPeriod)
}

func init() {
	rootCmd.AddCommand(vulnrichtmentCmd)
}
