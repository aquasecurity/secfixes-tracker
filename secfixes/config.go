package secfixes

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	DBPath    string `toml:"db_path"`
	Rewriters []Rewriter
	Importers Importers
}

type Rewriter struct {
	Field       string
	Predicate   string
	RewriteRule string `toml:"rewrite_rule"`
}

type Importers struct {
	Vulnrich Vulnrich
}

type Vulnrich struct {
	LookupPeriod time.Duration `toml:"lookup_period"`
}

func ParseConfig(config io.Reader) (c Config, err error) {
	tomlData, err := io.ReadAll(config)
	if err != nil {
		return c, fmt.Errorf("could not read config file: %w", err)
	}
	_, err = toml.Decode(string(tomlData), &c)
	if err != nil {
		return c, fmt.Errorf("could not decode toml: %w", err)
	}
	return c, nil
}

func ParseConfigFromFile(path string) (c Config, err error) {
	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("could not open config file: %w", err)
	}

	return ParseConfig(f)
}
