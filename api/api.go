package api

import (
	"context"
	"net/http"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/host-bench/benchmark"
	"go.sia.tech/hostd/wallet"
	"go.sia.tech/jape"
	"go.sia.tech/siad/modules"
	"go.uber.org/zap"
)

type (
	// A Syncer can connect to other peers and synchronize the blockchain.
	Syncer interface {
		Address() modules.NetAddress
		Peers() []modules.Peer
		Connect(addr modules.NetAddress) error
		Disconnect(addr modules.NetAddress) error
	}

	// A TPool manages the transaction pool
	TPool interface {
		RecommendedFee() (fee types.Currency)
		AcceptTransactionSet(txns []types.Transaction) error
	}

	// A ChainManager retrieves the current blockchain state
	ChainManager interface {
		Synced() bool
		TipState() consensus.State
	}

	// A Benchmark benchmarks hosts and manages contracts
	Benchmark interface {
		BenchmarkHost(ctx context.Context, hostAddr string, hostKey types.PublicKey, sectors uint64) (res benchmark.Result, _ error)
	}

	// A Wallet manages Siacoins and funds transactions
	Wallet interface {
		Address() types.Address
		ScanHeight() uint64
		Balance() (spendable, confirmed, unconfirmed types.Currency, err error)
		UnconfirmedTransactions() ([]wallet.Transaction, error)
		FundTransaction(txn *types.Transaction, amount types.Currency) (toSign []types.Hash256, release func(), err error)
		SignTransaction(cs consensus.State, txn *types.Transaction, toSign []types.Hash256, cf types.CoveredFields) error
		Transactions(limit, offset int) ([]wallet.Transaction, error)
	}

	api struct {
		log *zap.Logger

		syncer Syncer
		chain  ChainManager
		tpool  TPool
		bench  Benchmark
		wallet Wallet
	}
)

// NewServer initializes the API
func NewServer(g Syncer, chain ChainManager, tp TPool, bench Benchmark, wallet Wallet, log *zap.Logger) http.Handler {
	api := &api{
		log:    log,
		syncer: g,
		chain:  chain,
		tpool:  tp,
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
		"POST /benchmark": api.handlePOSTBenchmark,
		// wallet endpoints
		"GET /wallet":              api.handleGETWallet,
		"GET /wallet/transactions": api.handleGETWalletTransactions,
		"GET /wallet/pending":      api.handleGETWalletPending,
		"POST /wallet/send":        api.handlePOSTWalletSend,
	})
}
