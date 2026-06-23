package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/host-bench/api"
	"go.sia.tech/host-bench/benchmark"
	"go.sia.tech/host-bench/config"
	"go.sia.tech/host-bench/persist/sqlite"
	"go.uber.org/zap"
)

var explorerClient = &http.Client{Timeout: 30 * time.Second}

type explorer struct {
	url string
}

func (e *explorer) AddressCheckpoint(ctx context.Context, address types.Address) (index types.ChainIndex, err error) {
	err = makeExplorerRequest(ctx, http.MethodGet, fmt.Sprintf("%s/addresses/%s/checkpoint", e.url, address), nil, &index)
	return
}

func (e *explorer) TipHeight(ctx context.Context, height uint64) (index types.ChainIndex, err error) {
	err = makeExplorerRequest(ctx, http.MethodGet, fmt.Sprintf("%s/consensus/tip/%d", e.url, height), nil, &index)
	return
}

func defaultDataDirectory(fp string) string {
	// use the provided path if it's not empty
	if fp != "" {
		return fp
	}

	// check for databases in the current directory
	if _, err := os.Stat("benchy.sqlite3"); err == nil {
		return "."
	} else if _, err := os.Stat("consensus.db"); err == nil {
		return "."
	}

	// default to the operating system's application directory
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "benchyd")
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "benchyd")
	case "linux", "freebsd", "openbsd":
		return filepath.Join(string(filepath.Separator), "var", "lib", "benchyd")
	default:
		return "."
	}
}

func drainAndClose(r io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(r, 1024*1024))
	r.Close()
}

func makeExplorerRequest(ctx context.Context, method, url string, requestBody, response any) error {
	var body io.Reader
	if requestBody != nil {
		js, _ := json.Marshal(requestBody)
		body = bytes.NewReader(js)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := explorerClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return fmt.Errorf("unexpected status code: %d, failed to read response body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(buf))
	}

	if response == nil {
		return nil
	} else if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func newExplorer(url string) *explorer {
	return &explorer{url: strings.TrimRight(url, "/")}
}

func defaultExplorerURL(network string) string {
	switch network {
	case "zen":
		return "https://api.siascan.com/zen"
	default:
		return "https://api.siascan.com"
	}
}

func consensusExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "consensus.db"))
	return !errors.Is(err, os.ErrNotExist)
}

func splitPeers(peers string) []string {
	var result []string
	for peer := range strings.SplitSeq(peers, ",") {
		peer = strings.TrimSpace(peer)
		if peer != "" {
			result = append(result, peer)
		}
	}
	return result
}

func selectNetwork(name string, bootstrap bool, userPeers []string) (*consensus.Network, types.Block, []string, error) {
	peers := append([]string(nil), userPeers...)
	switch name {
	case "mainnet":
		network, genesisBlock := chain.Mainnet()
		if bootstrap {
			peers = append(peers, syncer.MainnetBootstrapPeers...)
		}
		return network, genesisBlock, peers, nil
	case "zen":
		network, genesisBlock := chain.TestnetZen()
		if bootstrap {
			peers = append(peers, syncer.ZenBootstrapPeers...)
		}
		return network, genesisBlock, peers, nil
	default:
		return nil, types.Block{}, nil, errors.New("invalid network: must be one of 'mainnet' or 'zen'")
	}
}

func setupChain(ctx context.Context, dir string, store *sqlite.Store, network *consensus.Network, genesisBlock types.Block, peers []string, walletAddress types.Address, exp *explorer, instant bool, log *zap.Logger) (*chain.Manager, func() error, error) {
	dbPath := filepath.Join(dir, "consensus.db")
	hasConsensusDB := consensusExists(dir)
	var (
		bdb      *coreutils.BoltChainDB
		dbstore  *chain.DBStore
		err      error
		tipState consensus.State
	)

	openDB := func() error {
		var err error
		bdb, err = coreutils.OpenBoltChainDB(dbPath)
		if err != nil {
			return fmt.Errorf("failed to open consensus database: %w", err)
		}
		return nil
	}

	closeDB := func() error {
		if bdb == nil {
			return nil
		}
		return bdb.Close()
	}
	if instant && !hasConsensusDB {
		if exp == nil {
			return nil, nil, errors.New("instant sync requires an explorer URL")
		} else if len(peers) == 0 {
			return nil, nil, errors.New("instant sync requires at least one syncer peer")
		}

		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		checkpoint, err := exp.AddressCheckpoint(ctx, walletAddress)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get address checkpoint from explorer: %w", err)
		}
		blocksPerDay := uint64(24 * time.Hour / network.BlockInterval)
		if checkpoint.Height > blocksPerDay {
			checkpoint.Height -= blocksPerDay
		} else {
			checkpoint.Height = 0
		}
		checkpoint, err = exp.TipHeight(ctx, checkpoint.Height)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get checkpoint height from explorer: %w", err)
		} else if checkpoint.Height < network.HardforkV2.RequireHeight {
			return nil, nil, fmt.Errorf("unable to instant sync: checkpoint height %d is before hardfork v2 require height %d", checkpoint.Height, network.HardforkV2.RequireHeight)
		}
		log.Info("starting instant sync from checkpoint", zap.Stringer("checkpoint", checkpoint))

		cs, block, err := syncer.RetrieveCheckpoint(ctx, peers, checkpoint, network, genesisBlock.ID())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve checkpoint: %w", err)
		}
		if err := store.ResetChainState(); err != nil {
			return nil, nil, fmt.Errorf("failed to reset wallet chain state: %w", err)
		} else if err := store.SetCheckpoint(checkpoint); err != nil {
			return nil, nil, fmt.Errorf("failed to set wallet checkpoint: %w", err)
		}
		if err := openDB(); err != nil {
			return nil, nil, err
		}
		dbstore, tipState, err = chain.NewDBStoreAtCheckpoint(bdb, cs, block, chain.NewZapMigrationLogger(log.Named("chain")))
		if err != nil {
			closeDB()
			return nil, nil, fmt.Errorf("failed to create chain store from checkpoint: %w", err)
		}
		log.Info("instant sync complete")
	} else {
		if instant {
			log.Warn("instant sync skipped: consensus database already exists")
		}
		if err := openDB(); err != nil {
			return nil, nil, err
		}
		dbstore, tipState, err = chain.NewDBStore(bdb, network, genesisBlock, chain.NewZapMigrationLogger(log.Named("chain")))
		if err != nil {
			closeDB()
			return nil, nil, fmt.Errorf("failed to create chain store: %w", err)
		}
	}

	return chain.NewManager(dbstore, tipState, chain.WithLog(log.Named("chain"))), closeDB, nil
}

func advertisedSyncerAddress(l net.Listener, configured string) string {
	addr := l.Addr().String()
	if configured != "" {
		addr = configured
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

func startWalletIndexer(ctx context.Context, cm *chain.Manager, store *sqlite.Store, w *wallet.SingleAddressWallet, log *zap.Logger) func() {
	ctx, cancel := context.WithCancel(ctx)
	updates := make(chan struct{}, 1)
	updates <- struct{}{}

	stopReorg := cm.OnReorg(func(types.ChainIndex) {
		select {
		case updates <- struct{}{}:
		default:
		}
	})

	go func() {
		defer stopReorg()
		for {
			select {
			case <-ctx.Done():
				return
			case <-updates:
			}
			for {
				if err := syncWalletIndex(ctx, cm, store, w); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Warn("failed to sync wallet index", zap.Error(err))
					select {
					case <-ctx.Done():
						return
					case <-time.After(30 * time.Second):
					}
				} else {
					break
				}
			}
		}
	}()
	return cancel
}

func syncWalletIndex(ctx context.Context, cm *chain.Manager, store *sqlite.Store, w *wallet.SingleAddressWallet) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		index, err := store.Tip()
		if err != nil {
			return fmt.Errorf("failed to get wallet tip: %w", err)
		}
		if index == cm.Tip() {
			return nil
		}

		reverted, applied, err := cm.UpdatesSince(index, 100)
		if err != nil {
			return fmt.Errorf("failed to get chain updates since %v: %w", index, err)
		} else if len(reverted)+len(applied) == 0 {
			return nil
		}

		next := index
		if len(applied) > 0 {
			next = applied[len(applied)-1].State.Index
		} else if len(reverted) > 0 {
			next = reverted[len(reverted)-1].State.Index
		}

		if err := store.UpdateChainState(func(tx sqlite.WalletUpdateTx) error {
			if err := w.UpdateChainState(tx, reverted, applied); err != nil {
				return err
			}
			return tx.SetLastIndex(next)
		}); err != nil {
			return fmt.Errorf("failed to update wallet chain state: %w", err)
		}
	}
}

func runNode(ctx context.Context, cfg config.Config, renterKey types.PrivateKey, instantSync bool, log *zap.Logger) error {
	apiListener, err := net.Listen("tcp", cfg.HTTP.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on api address %q: %w", cfg.HTTP.Address, err)
	}
	defer apiListener.Close()

	store, err := sqlite.OpenDatabase(filepath.Join(cfg.Directory, "benchy.sqlite3"), log.Named("sqlite"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer store.Close()

	walletHash := types.HashBytes(renterKey[:])
	if err := store.VerifyWalletKey(walletHash); errors.Is(err, wallet.ErrDifferentSeed) {
		if err := store.ResetChainState(); err != nil {
			return fmt.Errorf("failed to reset chain state after wallet seed change: %w", err)
		} else if err := store.UpdateWalletHash(walletHash); err != nil {
			return fmt.Errorf("failed to update wallet hash: %w", err)
		}
		log.Info("chain state reset due to wallet seed change")
	} else if err != nil {
		return fmt.Errorf("failed to verify wallet key: %w", err)
	}

	network, genesisBlock, peers, err := selectNetwork(cfg.Consensus.Network, cfg.Syncer.Bootstrap, cfg.Syncer.Peers)
	if err != nil {
		return fmt.Errorf("failed to select network: %w", err)
	}

	explorerURL := cfg.Explorer.URL
	if explorerURL == "" {
		explorerURL = defaultExplorerURL(cfg.Consensus.Network)
	}

	cm, closeChainDB, err := setupChain(ctx, cfg.Directory, store, network, genesisBlock, peers, types.StandardUnlockHash(renterKey.PublicKey()), newExplorer(explorerURL), instantSync, log)
	if err != nil {
		return fmt.Errorf("failed to set up chain manager: %w", err)
	}
	defer closeChainDB()

	syncerListener, err := net.Listen("tcp", cfg.Syncer.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on syncer address %q: %w", cfg.Syncer.Address, err)
	}
	defer syncerListener.Close()

	peerStore, err := sqlite.NewPeerStore(store)
	if err != nil {
		return fmt.Errorf("failed to create peer store: %w", err)
	}
	for _, peer := range peers {
		if err := peerStore.AddPeer(peer); err != nil {
			log.Warn("failed to add peer", zap.String("address", peer), zap.Error(err))
		}
	}

	advertisedAddr := advertisedSyncerAddress(syncerListener, cfg.Syncer.Address)
	s := syncer.New(syncerListener, cm, peerStore, gateway.Header{
		GenesisID:  genesisBlock.ID(),
		UniqueID:   gateway.GenerateUniqueID(),
		NetAddress: advertisedAddr,
	}, syncer.WithLogger(log.Named("syncer")))
	go func() {
		if err := s.Run(); err != nil && ctx.Err() == nil {
			log.Error("syncer stopped", zap.Error(err))
		}
	}()
	defer s.Close()

	w, err := wallet.NewSingleAddressWallet(renterKey, cm, store, s, wallet.WithLogger(log.Named("wallet")), wallet.WithReservationDuration(3*time.Hour))
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}
	defer w.Close()

	stopWalletIndexer := startWalletIndexer(ctx, cm, store, w, log.Named("wallet.index"))
	defer stopWalletIndexer()

	b := benchmark.New(renterKey, cm, w, log.Named("benchmark"))

	web := http.Server{
		Handler:     api.NewServer(s, cm, b, w, log.Named("api")),
		ReadTimeout: 30 * time.Second,
	}
	defer web.Close()

	go func() {
		err := web.Serve(apiListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("failed to serve web", zap.Error(err))
		}
	}()

	log.Info("benchyd started",
		zap.Stringer("apiAddress", apiListener.Addr()),
		zap.Stringer("syncerAddress", syncerListener.Addr()),
		zap.Stringer("walletAddress", w.Address()),
		zap.String("network", cfg.Consensus.Network),
		zap.Bool("instantSync", instantSync))

	<-ctx.Done()
	return nil
}
