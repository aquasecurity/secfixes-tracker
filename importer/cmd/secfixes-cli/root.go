package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/spf13/cobra"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
	"gorm.io/gorm"
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)
	config, err := secfixes.ParseConfigFromFile("config/application.toml")
	if err != nil {
		return fmt.Errorf("error reading 'application.toml': %w", err)
	}
	_app.Config = config
	db, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		PrepareStmt:            true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return fmt.Errorf("could not open secfixes.db: %w", err)
	}
	_app.DB = db

	err = rootCmd.Execute()
	if err != nil {
		return err
	}
	return nil
}
