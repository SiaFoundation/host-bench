package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func ansiStyle(style, output string) string {
	if cfg.Log.StdOut.EnableANSI {
		return fmt.Sprintf("\033[%sm%s\033[0m", style, output)
	}
	return output
}

func stdoutError(msg string) {
	fmt.Println(ansiStyle("31", msg))
}

func readInput(context string) string {
	fmt.Printf("%s: ", context)
	r := bufio.NewReader(os.Stdin)
	input, err := r.ReadString('\n')
	checkFatalError("failed to read input", err)
	return strings.TrimSpace(input)
}

func readPasswordInput(context string) string {
	fmt.Printf("%s: ", context)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	checkFatalError("failed to read password input", err)
	fmt.Println("")
	return string(input)
}

func promptYesNo(question string) bool {
	for {
		input := strings.ToLower(readInput(fmt.Sprintf("%s (yes/no)", question)))
		switch input {
		case "yes", "y":
			return true
		case "no", "n":
			return false
		default:
			stdoutError(`Answer must be "yes" or "no"`)
		}
	}
}

func setListenAddress(context string, value *string) {
	for {
		input := readInput(fmt.Sprintf("%s (currently %q)", context, *value))
		if input == "" {
			return
		}

		host, port, err := net.SplitHostPort(input)
		if err != nil {
			stdoutError(fmt.Sprintf("Invalid %s %q: %s", context, input, err))
			continue
		} else if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			stdoutError(fmt.Sprintf("Invalid %s port %q: must be between 0 and 65535", context, port))
			continue
		}
		*value = net.JoinHostPort(host, port)
		return
	}
}

func setDataDirectory() {
	if cfg.Directory == "" {
		cfg.Directory = "."
	}

	dir, err := filepath.Abs(cfg.Directory)
	checkFatalError("failed to get absolute path of data directory", err)

	fmt.Println("The data directory is where benchyd will store its consensus and wallet data.")
	if !promptYesNo("Would you like to change the data directory? (Current: " + dir + ")") {
		return
	}
	cfg.Directory = readInput("Enter data directory")
}

func setSeedPhrase() {
	for {
		fmt.Println("")
		fmt.Println("Type in your 12-word seed phrase and press enter. If you do not have a seed phrase yet, type 'seed' to generate one.")
		phrase := readPasswordInput("Enter seed phrase")

		if strings.EqualFold(strings.TrimSpace(phrase), "seed") {
			var seed [32]byte
			phrase = wallet.NewSeedPhrase()
			checkFatalError("failed to generate seed", wallet.SeedFromPhrase(&seed, phrase))
			key := wallet.KeyFromSeed(&seed, 0)
			fmt.Println("")
			fmt.Println("A new seed phrase has been generated below. " + ansiStyle("1", "Write it down and keep it safe."))
			fmt.Println(ansiStyle("34;1", "Seed Phrase:"), phrase)
			fmt.Println(ansiStyle("34;1", "Wallet Address:"), types.StandardUnlockHash(key.PublicKey()))
			cfg.RecoveryPhrase = phrase
			return
		}

		var seed [32]byte
		if err := wallet.SeedFromPhrase(&seed, phrase); err != nil {
			stdoutError(fmt.Sprintf("Invalid seed phrase: %s", err))
			continue
		}
		cfg.RecoveryPhrase = phrase
		return
	}
}

func setAdvancedConfig() {
	if !promptYesNo("Would you like to configure advanced settings?") {
		return
	}

	fmt.Println("")
	fmt.Println("The API address is used to serve the benchyd API. Leave blank to keep the current value.")
	setListenAddress("API Address", &cfg.HTTP.Address)

	fmt.Println("")
	fmt.Println("The syncer address is used to exchange blocks with other nodes in the Sia network. Leave blank to keep the current value.")
	setListenAddress("Syncer Address", &cfg.Syncer.Address)
}

func configPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "benchyd", "benchy.yml")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "benchyd", "benchy.yml")
	case "linux", "freebsd", "openbsd":
		return filepath.Join(string(filepath.Separator), "etc", "benchyd", "benchy.yml")
	default:
		return "benchy.yml"
	}
}

func runConfigCmd(fp string) {
	fmt.Println("benchyd Configuration Wizard")
	fmt.Println("This wizard will help you configure benchyd for the first time.")

	if fp == "" {
		fp = configPath()
	}
	fp, err := filepath.Abs(fp)
	checkFatalError("failed to get absolute path of config file", err)

	fmt.Println("")
	fmt.Printf("Config Location %q\n", fp)

	if _, err := os.Stat(fp); err == nil {
		if !promptYesNo(fmt.Sprintf("%q already exists. Would you like to overwrite it?", fp)) {
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		checkFatalError("failed to check if config file exists", err)
	} else {
		checkFatalError("failed to create config directory", os.MkdirAll(filepath.Dir(fp), 0700))
	}

	fmt.Println("")
	setDataDirectory()

	fmt.Println("")
	if cfg.RecoveryPhrase != "" {
		fmt.Println(ansiStyle("33", "A wallet seed phrase is already set."))
		if promptYesNo("Would you like to change your wallet seed phrase?") {
			setSeedPhrase()
		}
	} else {
		setSeedPhrase()
	}

	fmt.Println("")
	setAdvancedConfig()

	f, err := os.Create(fp)
	checkFatalError("failed to create config file", err)
	defer f.Close()

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	defer enc.Close()

	checkFatalError("failed to encode config file", enc.Encode(cfg))
	checkFatalError("failed to sync config file", f.Sync())

	fmt.Println("")
	fmt.Println(ansiStyle("32", "Configuration saved to "+fp))
}
