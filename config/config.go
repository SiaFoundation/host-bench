package config

import (
	"bytes"
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type (
	// HTTP contains the configuration for the HTTP API server.
	HTTP struct {
		Address string `yaml:"address,omitempty"`
	}

	// Syncer contains the configuration for the p2p syncer.
	Syncer struct {
		Address   string   `yaml:"address,omitempty"`
		Bootstrap bool     `yaml:"bootstrap,omitempty"`
		Peers     []string `yaml:"peers,omitempty"`
	}

	// Consensus contains the configuration for the consensus set.
	Consensus struct {
		Network string `yaml:"network,omitempty"`
	}

	// ExplorerData contains the configuration for using an external explorer.
	ExplorerData struct {
		URL string `yaml:"url,omitempty"`
	}

	// LogFile configures the file output of the logger.
	LogFile struct {
		Enabled bool            `yaml:"enabled,omitempty"`
		Level   zap.AtomicLevel `yaml:"level,omitempty"`
		Format  string          `yaml:"format,omitempty"`
		Path    string          `yaml:"path,omitempty"`
	}

	// StdOut configures the standard output of the logger.
	StdOut struct {
		Enabled    bool            `yaml:"enabled,omitempty"`
		Level      zap.AtomicLevel `yaml:"level,omitempty"`
		Format     string          `yaml:"format,omitempty"`
		EnableANSI bool            `yaml:"enableANSI,omitempty"` //nolint:tagliatelle
	}

	// Log contains the configuration for the logger.
	Log struct {
		StdOut StdOut  `yaml:"stdout,omitempty"`
		File   LogFile `yaml:"file,omitempty"`
	}

	// Config contains the configuration for benchyd.
	Config struct {
		Directory      string `yaml:"directory,omitempty"`
		RecoveryPhrase string `yaml:"recoveryPhrase,omitempty"`

		HTTP      HTTP         `yaml:"http,omitempty"`
		Syncer    Syncer       `yaml:"syncer,omitempty"`
		Consensus Consensus    `yaml:"consensus,omitempty"`
		Explorer  ExplorerData `yaml:"explorer,omitempty"`
		Log       Log          `yaml:"log,omitempty"`
	}
)

// LoadFile loads the configuration from the provided file path, merging it into
// cfg. If the file does not exist, an error wrapping os.ErrNotExist is returned.
func LoadFile(fp string, cfg *Config) error {
	buf, err := os.ReadFile(fp)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(buf))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}
	return nil
}
