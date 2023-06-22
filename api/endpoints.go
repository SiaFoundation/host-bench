package api

import (
	"errors"
	"fmt"
	"net/http"

	"go.sia.tech/core/types"
	"go.sia.tech/jape"
	"go.sia.tech/siad/modules"
	"go.uber.org/zap"
)

const stdTxnSize = 1200

// checkServerError conditionally writes an error to the response if err is not
// nil.
func (a *api) checkServerError(c jape.Context, context string, err error) bool {
	if err != nil {
		c.Error(err, http.StatusInternalServerError)
		a.log.Warn(context, zap.Error(err))
	}
	return err == nil
}

func (a *api) handleGETConsensusState(c jape.Context) {
	c.Encode(ConsensusState{
		Synced:     a.chain.Synced(),
		ChainIndex: a.chain.TipState().Index,
	})
}

func (a *api) handleGETSyncerAddr(c jape.Context) {
	c.Encode(string(a.syncer.Address()))
}

func (a *api) handleGETSyncerPeers(c jape.Context) {
	p := a.syncer.Peers()
	peers := make([]Peer, len(p))
	for i, peer := range p {
		peers[i] = Peer{
			Address: string(peer.NetAddress),
			Version: peer.Version,
		}
	}
	c.Encode(peers)
}

func (a *api) handlePUTSyncerPeer(c jape.Context) {
	var req SyncerConnectRequest
	if err := c.Decode(&req); err != nil {
		return
	}
	err := a.syncer.Connect(modules.NetAddress(req.Address))
	a.checkServerError(c, "failed to connect to peer", err)
}

func (a *api) handleDeleteSyncerPeer(c jape.Context) {
	var addr modules.NetAddress
	if err := c.DecodeParam("address", &addr); err != nil {
		return
	}
	err := a.syncer.Disconnect(addr)
	a.checkServerError(c, "failed to disconnect from peer", err)
}

func (a *api) handlePOSTBenchmark(c jape.Context) {
	var req BenchmarkRequest
	if err := c.Decode(&req); err != nil {
		return
	}

	result, err := a.bench.BenchmarkHost(c.Request.Context(), req.Address, req.HostKey, req.Sectors)
	if err != nil {
		c.Error(err, http.StatusInternalServerError)
		a.log.Warn("failed to benchmark host", zap.Error(err))
		return
	}
	c.Encode(result)
}

func (a *api) handleGETWallet(c jape.Context) {
	spendable, confirmed, unconfirmed, err := a.wallet.Balance()
	if !a.checkServerError(c, "failed to get wallet", err) {
		return
	}
	c.Encode(WalletResponse{
		ScanHeight:  a.wallet.ScanHeight(),
		Address:     a.wallet.Address(),
		Spendable:   spendable,
		Confirmed:   confirmed,
		Unconfirmed: unconfirmed,
	})
}

func (a *api) handleGETWalletTransactions(c jape.Context) {
	limit, offset := parseLimitParams(c, 100, 500)

	transactions, err := a.wallet.Transactions(limit, offset)
	if !a.checkServerError(c, "failed to get wallet transactions", err) {
		return
	}
	c.Encode(transactions)
}

func (a *api) handleGETWalletPending(c jape.Context) {
	pending, err := a.wallet.UnconfirmedTransactions()
	if !a.checkServerError(c, "failed to get wallet pending", err) {
		return
	}
	c.Encode(pending)
}

func (a *api) handlePOSTWalletSend(c jape.Context) {
	var req WalletSendSiacoinsRequest
	if err := c.Decode(&req); err != nil {
		return
	} else if req.Address == types.VoidAddress {
		c.Error(errors.New("cannot send to void address"), http.StatusBadRequest)
		return
	}

	// estimate miner fee
	feePerByte := a.tpool.RecommendedFee()
	minerFee := feePerByte.Mul64(stdTxnSize)
	if req.SubtractMinerFee {
		var underflow bool
		req.Amount, underflow = req.Amount.SubWithUnderflow(minerFee)
		if underflow {
			c.Error(fmt.Errorf("amount must be greater than miner fee: %s", minerFee), http.StatusBadRequest)
			return
		}
	}

	// build transaction
	txn := types.Transaction{
		MinerFees: []types.Currency{minerFee},
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: req.Address, Value: req.Amount},
		},
	}
	// fund and sign transaction
	toSign, release, err := a.wallet.FundTransaction(&txn, req.Amount.Add(minerFee))
	if !a.checkServerError(c, "failed to fund transaction", err) {
		return
	}
	defer release()
	err = a.wallet.SignTransaction(a.chain.TipState(), &txn, toSign, types.CoveredFields{WholeTransaction: true})
	if !a.checkServerError(c, "failed to sign transaction", err) {
		return
	}
	// broadcast transaction
	err = a.tpool.AcceptTransactionSet([]types.Transaction{txn})
	if !a.checkServerError(c, "failed to broadcast transaction", err) {
		return
	}
	c.Encode(txn.ID())
}

func parseLimitParams(c jape.Context, defaultLimit, maxLimit int) (limit, offset int) {
	if err := c.DecodeForm("limit", &limit); err != nil {
		return
	} else if err := c.DecodeForm("offset", &offset); err != nil {
		return
	}
	if limit > maxLimit {
		limit = maxLimit
	} else if limit <= 0 {
		limit = defaultLimit
	}

	if offset < 0 {
		offset = 0
	}
	return
}
