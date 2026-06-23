package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/host-bench/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"lukechampine.com/flagg"
)

const (
	walletSeedEnvVar = "BENCHY_SEED"

	rootUsage = `Usage:
benchyd [flags] [command]

Run 'benchyd' with no command to start the benchmarking daemon.

Commands:
	version		Print the benchyd version
	seed		Generate a new wallet seed and print the corresponding address
	config		Interactively configure benchyd
`

	versionUsage = `Usage:
benchyd version

Print the version of benchyd.`

	seedUsage = `Usage:
benchyd seed

Generate a secure BIP-39 seed phrase and corresponding address. The seed phrase should be added to the config file or set as the BENCHY_SEED environment variable.`

	configUsage = `Usage:
benchyd config

Interactively configure benchyd. The resulting config will be saved to benchy.yml.`
)

var cfg = config.Config{
	RecoveryPhrase: os.Getenv(walletSeedEnvVar), // default to env variable

	HTTP: config.HTTP{
		Address: ":8484",
	},
	Syncer: config.Syncer{
		Address:   ":9981",
		Bootstrap: true,
	},
	Consensus: config.Consensus{
		Network: "mainnet",
	},
	Log: config.Log{
		StdOut: config.StdOut{
			Enabled:    true,
			Level:      zap.NewAtomicLevelAt(zap.InfoLevel),
			Format:     "human",
			EnableANSI: runtime.GOOS != "windows",
		},
		File: config.LogFile{
			Enabled: false,
		},
	},
}

// checkFatalError prints an error message to stderr and exits with a 1 exit
// code. If err is nil, this is a no-op.
func checkFatalError(context string, err error) {
	if err == nil {
		return
	}
	os.Stderr.WriteString(fmt.Sprintf("%s: %s\n", context, err))
	os.Exit(1)
}

// tryConfigPaths returns the paths benchyd searches for a config file, in order
// of precedence.
func tryConfigPaths() []string {
	paths := []string{"benchy.yml"}
	if cfg.Directory != "" {
		paths = append(paths, filepath.Join(cfg.Directory, "benchy.yml"))
	}

	switch runtime.GOOS {
	case "windows":
		paths = append(paths, filepath.Join(os.Getenv("APPDATA"), "benchyd", "benchy.yml"))
	case "darwin":
		paths = append(paths, filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "benchyd", "benchy.yml"))
	case "linux", "freebsd", "openbsd":
		paths = append(paths, filepath.Join(string(filepath.Separator), "etc", "benchyd", "benchy.yml"))
	}
	return paths
}

// tryLoadConfig tries to load a config file from the standard locations, merging
// it into cfg. If a config file is found and loaded, its path is returned.
func tryLoadConfig() string {
	for _, fp := range tryConfigPaths() {
		if err := config.LoadFile(fp, &cfg); err == nil {
			return fp
		} else if !errors.Is(err, os.ErrNotExist) {
			checkFatalError("failed to load config file", err)
		}
	}
	return ""
}

// jsonEncoder returns a zapcore.Encoder that encodes logs as JSON intended for
// parsing.
func jsonEncoder() zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	return zapcore.NewJSONEncoder(cfg)
}

// humanEncoder returns a zapcore.Encoder that encodes logs as human-readable
// text.
func humanEncoder(showColors bool) zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = ""
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg.EncodeDuration = zapcore.StringDurationEncoder
	if showColors {
		cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	}
	cfg.StacktraceKey = ""
	cfg.CallerKey = ""
	return zapcore.NewConsoleEncoder(cfg)
}

// initLogger builds the logger from cfg.Log and returns it along with a function
// to flush and close its outputs.
func initLogger() (*zap.Logger, func(), error) {
	if !cfg.Log.StdOut.Enabled && !cfg.Log.File.Enabled {
		return nil, nil, errors.New("either stdout or file logging must be enabled")
	}

	var closeFns []func()
	var cores []zapcore.Core
	if cfg.Log.StdOut.Enabled {
		var encoder zapcore.Encoder
		switch cfg.Log.StdOut.Format {
		case "json":
			encoder = jsonEncoder()
		default: // stdout defaults to human
			encoder = humanEncoder(cfg.Log.StdOut.EnableANSI)
		}
		cores = append(cores, zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), cfg.Log.StdOut.Level))
	}

	if cfg.Log.File.Enabled {
		if cfg.Log.File.Path == "" {
			cfg.Log.File.Path = filepath.Join(cfg.Directory, "benchyd.log")
		}

		var encoder zapcore.Encoder
		switch cfg.Log.File.Format {
		case "human":
			encoder = humanEncoder(false) // disable colors in file log
		default: // file defaults to JSON
			encoder = jsonEncoder()
		}

		fileWriter, closeFn, err := zap.Open(cfg.Log.File.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file: %w", err)
		}
		closeFns = append(closeFns, closeFn)
		cores = append(cores, zapcore.NewCore(encoder, zapcore.Lock(fileWriter), cfg.Log.File.Level))
	}

	log := zap.New(zapcore.NewTee(cores...), zap.AddCaller())
	return log, func() {
		log.Sync()
		for _, fn := range closeFns {
			fn()
		}
	}, nil
}

func main() {
	var instantSync bool
	// attempt to load the config file, command line flags will override any
	// values set in the config file
	configPath := tryLoadConfig()

	// set the data directory to the default if it is not set
	cfg.Directory = defaultDataDirectory(cfg.Directory)

	rootCmd := flagg.Root
	rootCmd.Usage = flagg.SimpleUsage(rootCmd, rootUsage)
	rootCmd.StringVar(&cfg.Directory, "dir", cfg.Directory, "data directory")
	rootCmd.StringVar(&cfg.HTTP.Address, "api.addr", cfg.HTTP.Address, "api address")
	rootCmd.StringVar(&cfg.Syncer.Address, "syncer.addr", cfg.Syncer.Address, "syncer address")
	rootCmd.BoolVar(&cfg.Syncer.Bootstrap, "bootstrap", cfg.Syncer.Bootstrap, "bootstrap peers")
	rootCmd.StringVar(&cfg.Consensus.Network, "network", cfg.Consensus.Network, "network: mainnet or zen")
	rootCmd.BoolVar(&instantSync, "instant", false, "instant sync from an explorer checkpoint")
	var levelOverride string
	rootCmd.StringVar(&levelOverride, "log.level", "", "log level override (debug, info, warn, error)")

	seedCmd := flagg.New("seed", seedUsage)
	configCmd := flagg.New("config", configUsage)
	versionCmd := flagg.New("version", versionUsage)

	cmd := flagg.Parse(flagg.Tree{
		Cmd: rootCmd,
		Sub: []flagg.Tree{
			{Cmd: seedCmd},
			{Cmd: configCmd},
			{Cmd: versionCmd},
		},
	})

	// override the log level if the flag is set
	if levelOverride != "" {
		var level zap.AtomicLevel
		checkFatalError("failed to parse log level", level.UnmarshalText([]byte(levelOverride)))
		cfg.Log.StdOut.Level = level
		cfg.Log.File.Level = level
	}

	switch cmd {
	case versionCmd:
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			return
		}

		commit, modified, buildTime := buildInfo()
		fmt.Println("benchyd")
		fmt.Println("Commit:", commit, map[bool]string{true: "(modified)", false: ""}[modified])
		fmt.Println("Build Date:", buildTime)
	case seedCmd:
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			return
		}

		var seed [32]byte
		phrase := wallet.NewSeedPhrase()
		checkFatalError("failed to generate seed", wallet.SeedFromPhrase(&seed, phrase))
		key := wallet.KeyFromSeed(&seed, 0)
		fmt.Println("Recovery Phrase:", phrase)
		fmt.Println("Address:", types.StandardUnlockHash(key.PublicKey()))
	case configCmd:
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			return
		}

		runConfigCmd(configPath)
	case rootCmd:
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			return
		}

		// check that the wallet seed is set
		if cfg.RecoveryPhrase == "" {
			checkFatalError("wallet seed not set", errors.New("wallet seed must be set via the "+walletSeedEnvVar+" environment variable or config file"))
		}

		// create the data directory if it does not already exist
		checkFatalError("failed to create data directory", os.MkdirAll(cfg.Directory, 0700))

		log, closeLog, err := initLogger()
		checkFatalError("failed to initialize logger", err)
		defer closeLog()
		zap.RedirectStdLog(log.Named("stdlib"))

		var seed [32]byte
		checkFatalError("failed to load wallet seed", wallet.SeedFromPhrase(&seed, cfg.RecoveryPhrase))
		renterKey := wallet.KeyFromSeed(&seed, 0)

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		checkFatalError("daemon startup failed", runNode(ctx, cfg, renterKey, instantSync, log))
	}
}

func buildInfo() (commit string, modified bool, buildTime string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		case "vcs.time":
			buildTime = s.Value
		}
	}
	return
}
