package api

import (
	"errors"
	"fmt"
	"net/http"

	"go.sia.tech/core/types"
	"go.sia.tech/jape"
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
	var synced bool
	for _, peer := range a.syncer.Peers() {
		if peer.Synced() {
			synced = true
			break
		}
	}
	c.Encode(ConsensusState{
		Synced:     synced,
		ChainIndex: a.chain.TipState().Index,
	})
}

func (a *api) handleGETSyncerAddr(c jape.Context) {
	c.Encode(a.syncer.Addr())
}

func (a *api) handleGETSyncerPeers(c jape.Context) {
	p := a.syncer.Peers()
	peers := make([]Peer, len(p))
	for i, peer := range p {
		peers[i] = Peer{
			Address: peer.Addr(),
			Version: peer.Version(),
			Synced:  peer.Synced(),
		}
	}
	c.Encode(peers)
}

func (a *api) handlePUTSyncerPeer(c jape.Context) {
	var req SyncerConnectRequest
	if err := c.Decode(&req); err != nil {
		return
	}
	_, err := a.syncer.Connect(c.Request.Context(), req.Address)
	a.checkServerError(c, "failed to connect to peer", err)
}

func (a *api) handleDeleteSyncerPeer(c jape.Context) {
	var addr string
	if err := c.DecodeParam("address", &addr); err != nil {
		return
	}
	for _, peer := range a.syncer.Peers() {
		if peer.Addr() == addr || peer.ConnAddr == addr {
			a.checkServerError(c, "failed to disconnect from peer", peer.Close())
			return
		}
	}
	c.Error(fmt.Errorf("peer %q not connected", addr), http.StatusNotFound)
}

func (a *api) handlePOSTScan(c jape.Context) {
	var req ScanRequest
	if err := c.Decode(&req); err != nil {
		return
	}
	settings, err := a.bench.ScanHost(c.Request.Context(), req.Address, req.HostKey)
	if !a.checkServerError(c, "failed to scan", err) {
		return
	}
	c.Encode(settings)
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
	balance, err := a.wallet.Balance()
	if !a.checkServerError(c, "failed to get wallet", err) {
		return
	}
	tip, err := a.wallet.Tip()
	if !a.checkServerError(c, "failed to get wallet tip", err) {
		return
	}
	c.Encode(WalletResponse{
		ScanHeight:  tip.Height,
		Address:     a.wallet.Address(),
		Spendable:   balance.Spendable,
		Confirmed:   balance.Confirmed,
		Unconfirmed: balance.Unconfirmed,
	})
}

func (a *api) handleGETWalletTransactions(c jape.Context) {
	limit, offset := parseLimitParams(c, 100, 500)

	transactions, err := a.wallet.Events(offset, limit)
	if !a.checkServerError(c, "failed to get wallet transactions", err) {
		return
	}
	c.Encode(transactions)
}

func (a *api) handleGETWalletPending(c jape.Context) {
	pending, err := a.wallet.UnconfirmedEvents()
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
	feePerByte := a.wallet.RecommendedFee()
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
	txn := types.V2Transaction{
		MinerFee: minerFee,
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: req.Address, Value: req.Amount},
		},
	}
	// fund and sign transaction
	basis, toSign, err := a.wallet.FundV2Transaction(&txn, req.Amount.Add(minerFee), false)
	if !a.checkServerError(c, "failed to fund transaction", err) {
		return
	}
	a.wallet.SignV2Inputs(&txn, toSign)
	basis, txnSet, err := a.chain.V2TransactionSet(basis, txn)
	if !a.checkServerError(c, "failed to create transaction set", err) {
		a.wallet.ReleaseInputs(nil, []types.V2Transaction{txn})
		return
	}
	// broadcast transaction
	err = a.wallet.BroadcastV2TransactionSet(basis, txnSet)
	if !a.checkServerError(c, "failed to broadcast transaction", err) {
		a.wallet.ReleaseInputs(nil, []types.V2Transaction{txn})
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
