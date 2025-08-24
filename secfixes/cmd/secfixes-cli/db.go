package main

import (
	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Commands to work with the database",
}

var dbCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Commands to cleanup the database",
}

var dbCleanRepoCmd = &cobra.Command{
	Use:   "repo <repo>",
	Short: "Remove package versions and vulnerability states for a specific repo",
	RunE:  runDBCleanRepo,
}

var gcFlags = struct {
	dryRun bool
}{}

var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply database migrations",
	RunE:  runDBMigrate,
}

func runDBCleanRepo(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return cmd.Usage()
	}

	repo := args[0]

	return secfixes.CleanupRepo(
		repo,
		gcFlags.dryRun,
		_app.DB,
	)
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
	return _app.DB.AutoMigrate(
		&secfixes.Vulnerability{},
		&secfixes.Package{},
		&secfixes.VulnerabilityReference{},
		&secfixes.PackageVersion{},
		&secfixes.CPEMatch{},
		&secfixes.VulnerabilityState{},
	)
}

func init() {
	dbCmd.PersistentFlags().BoolVarP(&gcFlags.dryRun, "dry-run", "n", false, "Only show the amount of records found")

	dbCleanCmd.AddCommand(dbCleanRepoCmd)
	dbCmd.AddCommand(dbCleanCmd)
	dbCmd.AddCommand(dbMigrateCmd)
	rootCmd.AddCommand(dbCmd)
}
