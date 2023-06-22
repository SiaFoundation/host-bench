package api

import (
	"go.sia.tech/core/types"
)

type (
	// SyncerConnectRequest is the request body for the [PUT] /syncer/peers endpoint.
	SyncerConnectRequest struct {
		Address string `json:"address"`
	}

	// ConsensusState is the response body for the [GET] /consensus endpoint.
	ConsensusState struct {
		Synced     bool             `json:"synced"`
		ChainIndex types.ChainIndex `json:"chainIndex"`
	}

	// A Peer is a peer in the network.
	Peer struct {
		Address string `json:"address"`
		Version string `json:"version"`
	}

	BenchmarkRequest struct {
		Address string          `json:"address"`
		HostKey types.PublicKey `json:"hostKey"`
		Sectors uint64          `json:"sectors"`
	}

	// WalletResponse is the response body for the [GET] /wallet endpoint.
	WalletResponse struct {
		ScanHeight  uint64         `json:"scanHeight"`
		Address     types.Address  `json:"address"`
		Spendable   types.Currency `json:"spendable"`
		Confirmed   types.Currency `json:"confirmed"`
		Unconfirmed types.Currency `json:"unconfirmed"`
	}

	// WalletSendSiacoinsRequest is the request body for the [POST] /wallet/send endpoint.
	WalletSendSiacoinsRequest struct {
		Address          types.Address  `json:"address"`
		Amount           types.Currency `json:"amount"`
		SubtractMinerFee bool           `json:"subtractMinerFee"`
	}
)
