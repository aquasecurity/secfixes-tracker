package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

var rootCmd = &cobra.Command{
	Short: "Import data into the secfixes tracker",
}

var _app app

type app struct {
	DB     *gorm.DB
	Config secfixes.Config
}

func App() app {
	return _app
}

func main() {
	err := run()
	if err != nil {
		fmt.Printf("FATAL: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	var err error
	_app, err = initApp()
	if err != nil {
		return err
	}

	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	err = rootCmd.Execute()
	if err != nil {
		return err
	}
	return nil
}

func initApp() (app, error) {
	var app app
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
	config, err := secfixes.ParseConfigFromFile("config/application.toml")
	if err != nil {
		return app, fmt.Errorf("error reading 'application.toml': %w", err)
	}
	app.Config = config
	db, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		PrepareStmt:            true,
		SkipDefaultTransaction: true,
		Logger:                 gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return app, fmt.Errorf("could not open secfixes.db: %w", err)
	}
	app.DB = db

	return app, nil
}
