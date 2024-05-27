package main

import (
	"time"

	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/importer"
)

var nvdCmd = &cobra.Command{
	Use:   "import-nvd",
	Short: "Import NVD secfixes",
	RunE:  runImportNVD,
}

func runImportNVD(cmd *cobra.Command, args []string) error {
	err := importer.NVDFeed(
		App().DB,
		&importer.APIv2{},
		App().Config,
		7*24*time.Hour,
	)
	return err
}

func init() {
	rootCmd.AddCommand(nvdCmd)
}
