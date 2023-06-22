package main

import (
	"context"
	"errors"
	"flag"
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

	"net/http"
)

var (
	dir            string
	bootstrapPeers bool
	apiAddr        string
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
	flag.StringVar(&dir, "dir", ".", "data directory")
	flag.StringVar(&apiAddr, "api.addr", ":8484", "api address")
	flag.StringVar(&logLevel, "log.level", "info", "log level")
	flag.BoolVar(&bootstrapPeers, "bootstrap", false, "bootstrap peers")
	flag.Parse()

	if flag.Arg(0) == "seed" {
		var seed [32]byte
		phrase := cw.NewSeedPhrase()
		if err := cw.SeedFromPhrase(&seed, phrase); err != nil {
			log.Fatal(err)
		}
		key := cw.KeyFromSeed(&seed, 0)
		log.Println("seed phrase:", phrase)
		log.Println("address:", key.PublicKey().StandardAddress())
		return
	}

	renterKey := getWalletSeed()

	apiListener, err := net.Listen("tcp", apiAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer apiListener.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()

		time.Sleep(30 * time.Second)
		os.Exit(1)
	}()

	g, err := gateway.NewCustomGateway(":9981", bootstrapPeers, false, filepath.Join(dir, "gateway"), modules.ProdDependencies)
	if err != nil {
		log.Fatalln(err)
	}
	defer g.Close()

	cs, errCh := consensus.New(g, bootstrapPeers, filepath.Join(dir, "consensus"))
	if err := <-errCh; err != nil {
		log.Fatalln(err)
	}
	defer cs.Close()

	tp, err := transactionpool.New(cs, g, filepath.Join(dir, "transactionpool"))
	if err != nil {
		log.Fatalln(err)
	}
	defer tp.Close()

	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout", filepath.Join(dir, "log.log")}
	switch logLevel {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("ERROR: failed to create logger:", err)
	}
	defer logger.Sync()

	db, err := sqlite.OpenDatabase(filepath.Join(dir, "benchy.sqlite3"), logger.Named("sqlite"))
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	cm, err := chain.NewManager(cs)
	if err != nil {
		log.Fatalln(err)
	}

	w, err := wallet.NewSingleAddressWallet(renterKey, cm, txpool{tp}, db, logger.Named("wallet"))
	if err != nil {
		log.Fatalln(err)
	}
	defer w.Close()

	b := benchmark.New(renterKey, cm, txpool{tp}, w, logger.Named("benchmark"))

	web := http.Server{
		Handler:     api.NewServer(g, cm, txpool{tp}, b, w, logger.Named("api")),
		ReadTimeout: 30 * time.Second,
	}
	defer web.Close()

	go func() {
		err := web.Serve(apiListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("failed to serve web", zap.Error(err))
		}
	}()

	<-ctx.Done()
}
