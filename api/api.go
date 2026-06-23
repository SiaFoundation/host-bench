package api

import (
	"context"
	"net/http"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/host-bench/benchmark"
	"go.sia.tech/jape"
	"go.uber.org/zap"
)

type (
	// A Syncer can connect to other peers and synchronize the blockchain.
	Syncer interface {
		Addr() string
		Peers() []*syncer.Peer
		Connect(ctx context.Context, addr string) (*syncer.Peer, error)
	}

	// A ChainManager retrieves the current blockchain state
	ChainManager interface {
		TipState() consensus.State
		V2TransactionSet(basis types.ChainIndex, txn types.V2Transaction) (types.ChainIndex, []types.V2Transaction, error)
	}

	// A Benchmark benchmarks hosts and manages contracts
	Benchmark interface {
		BenchmarkHost(ctx context.Context, hostAddr string, hostKey types.PublicKey, sectors uint64) (benchmark.Result, error)
		ScanHost(ctx context.Context, hostAddr string, hostKey types.PublicKey) (benchmark.Settings, error)
	}

	// A Wallet manages Siacoins and funds transactions
	Wallet interface {
		Address() types.Address
		Tip() (types.ChainIndex, error)
		Balance() (wallet.Balance, error)
		Events(offset, limit int) ([]wallet.Event, error)
		UnconfirmedEvents() ([]wallet.Event, error)
		FundV2Transaction(txn *types.V2Transaction, amount types.Currency, useUnconfirmed bool) (types.ChainIndex, []int, error)
		SignV2Inputs(txn *types.V2Transaction, toSign []int)
		ReleaseInputs(txns []types.Transaction, v2txns []types.V2Transaction)
		BroadcastV2TransactionSet(index types.ChainIndex, txns []types.V2Transaction) error
		RecommendedFee() types.Currency
	}

	api struct {
		log *zap.Logger

		syncer Syncer
		chain  ChainManager
		bench  Benchmark
		wallet Wallet
	}
)

// NewServer initializes the API
func NewServer(g Syncer, chain ChainManager, bench Benchmark, wallet Wallet, log *zap.Logger) http.Handler {
	api := &api{
		log:    log,
		syncer: g,
		chain:  chain,
		wallet: wallet,
		bench:  bench,
	}
	return jape.Mux(map[string]jape.Handler{
		// state endpoints
		"GET /state/consensus": api.handleGETConsensusState,
		// gateway endpoints
		"GET /syncer/address":           api.handleGETSyncerAddr,
		"GET /syncer/peers":             api.handleGETSyncerPeers,
		"PUT /syncer/peers":             api.handlePUTSyncerPeer,
		"DELETE /syncer/peers/:address": api.handleDeleteSyncerPeer,
		// benchmark endpoints
		"POST /scan":      api.handlePOSTScan,
		"POST /benchmark": api.handlePOSTBenchmark,
		// wallet endpoints
		"GET /wallet":              api.handleGETWallet,
		"GET /wallet/transactions": api.handleGETWalletTransactions,
		"GET /wallet/pending":      api.handleGETWalletPending,
		"POST /wallet/send":        api.handlePOSTWalletSend,
	})
}
