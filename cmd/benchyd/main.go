package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.sia.tech/core/types"
	cw "go.sia.tech/core/wallet"
	"go.sia.tech/host-bench/api"
	"go.sia.tech/host-bench/benchmark"
	"go.sia.tech/host-bench/chain"
	"go.sia.tech/host-bench/persist/sqlite"
	"go.sia.tech/hostd/wallet"
	"go.sia.tech/siad/modules"
	"go.sia.tech/siad/modules/consensus"
	"go.sia.tech/siad/modules/gateway"
	"go.sia.tech/siad/modules/transactionpool"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"net/http"
)

var (
	dir            string
	bootstrapPeers bool
	apiAddr        string
	gatewayAddr    string
	logLevel       string
)

func getWalletSeed() (renterKey types.PrivateKey) {
	recoveryPhrase := os.Getenv("BENCHY_SEED")

	var seed [32]byte
	if err := cw.SeedFromPhrase(&seed, recoveryPhrase); err != nil {
		log.Fatalln("unable to parse seed:", err)
	}
	return cw.KeyFromSeed(&seed, 0)
}

func main() {
	// configure console logging note: this is configured before anything else
	// to have consistent logging. File logging will be added after the cli
	// flags and config is parsed
	consoleCfg := zap.NewProductionEncoderConfig()
	consoleCfg.TimeKey = "" // prevent duplicate timestamps
	consoleCfg.EncodeTime = zapcore.RFC3339TimeEncoder
	consoleCfg.EncodeDuration = zapcore.StringDurationEncoder
	consoleCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleCfg.StacktraceKey = ""
	consoleCfg.CallerKey = ""
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg)

	// only log info messages to console unless stdout logging is enabled
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), zap.NewAtomicLevelAt(zap.InfoLevel))
	log := zap.New(consoleCore, zap.AddCaller())
	defer log.Sync()
	// redirect stdlib log to zap
	zap.RedirectStdLog(log.Named("stdlib"))

	flag.StringVar(&dir, "dir", ".", "data directory")
	flag.StringVar(&apiAddr, "api.addr", ":8484", "api address")
	flag.StringVar(&gatewayAddr, "rpc", defaultGatewayAddr, "gateway address")
	flag.StringVar(&logLevel, "log.level", "info", "log level")
	flag.BoolVar(&bootstrapPeers, "bootstrap", false, "bootstrap peers")
	flag.Parse()

	if flag.Arg(0) == "seed" {
		var seed [32]byte
		phrase := cw.NewSeedPhrase()
		if err := cw.SeedFromPhrase(&seed, phrase); err != nil {
			panic(err)
		}
		key := cw.KeyFromSeed(&seed, 0)
		fmt.Println("seed phrase:", phrase)
		fmt.Println("address:", key.PublicKey().StandardAddress())
		return
	}

	renterKey := getWalletSeed()

	// configure logging
	var level zap.AtomicLevel
	switch logLevel {
	case "debug":
		level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		log.Fatal("invalid log level", zap.String("level", logLevel))
	}

	// create the data directory if it does not already exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal("unable to create config directory", zap.Error(err))
	}

	fileCfg := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(fileCfg)

	fileWriter, closeFn, err := zap.Open(filepath.Join(dir, "benchyd.log"))
	if err != nil {
		fmt.Println("failed to open log file:", err)
		os.Exit(1)
	}
	defer closeFn()

	// wrap the logger to log to both stdout and the log file
	log = log.WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
		// use a tee to log to both stdout and the log file
		return zapcore.NewTee(
			zapcore.NewCore(fileEncoder, zapcore.Lock(fileWriter), level),
			zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), level),
		)
	}))

	apiListener, err := net.Listen("tcp", apiAddr)
	if err != nil {
		log.Fatal("failed to listen on api address", zap.Error(err), zap.String("addr", apiAddr))
	}
	defer apiListener.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()

		time.Sleep(30 * time.Second)
		os.Exit(1)
	}()

	g, err := gateway.NewCustomGateway(gatewayAddr, bootstrapPeers, false, filepath.Join(dir, "gateway"), modules.ProdDependencies)
	if err != nil {
		log.Fatal("failed to create gateway", zap.Error(err))
	}
	defer g.Close()

	cs, errCh := consensus.New(g, bootstrapPeers, filepath.Join(dir, "consensus"))
	if err := <-errCh; err != nil {
		log.Fatal("failed to start consensus", zap.Error(err))
	}
	defer cs.Close()

	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "transactionpool"))
	if err != nil {
		log.Fatal("failed to start tpool", zap.Error(err))
	}
	defer tp.Close()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "benchy.sqlite3"), log.Named("sqlite"))
	if err != nil {
		log.Fatal("failed to open database", zap.Error(err))
	}
	defer db.Close()

	cm, err := chain.NewManager(cs)
	if err != nil {
		log.Fatal("failed to create chain manager", zap.Error(err))
	}

	w, err := wallet.NewSingleAddressWallet(renterKey, cm, txpool{tp}, db, log.Named("wallet"))
	if err != nil {
		log.Fatal("failed to create wallet", zap.Error(err))
	}
	defer w.Close()

	b := benchmark.New(renterKey, cm, txpool{tp}, w, log.Named("benchmark"))

	web := http.Server{
		Handler:     api.NewServer(g, cm, txpool{tp}, b, w, log.Named("api")),
		ReadTimeout: 30 * time.Second,
	}
	defer web.Close()

	go func() {
		err := web.Serve(apiListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("failed to serve web", zap.Error(err))
		}
	}()

	log.Info("benchyd started", zap.Stringer("apiAddress", apiListener.Addr()), zap.Stringer("walletAddress", w.Address()))

	<-ctx.Done()
}
