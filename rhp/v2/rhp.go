package rhp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"go.sia.tech/core/consensus"
	rhp2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

const (
	defaultMaxMessageSize = 4096
	largeMaxMessageSize   = 1 << 20
)

type (
	// A ChainManager is used to get the current consensus state
	ChainManager interface {
		TipState() consensus.State
	}

	// A Wallet funds and signs transactions
	Wallet interface {
		Address() types.Address
		FundTransaction(txn *types.Transaction, amount types.Currency) ([]types.Hash256, func(), error)
		SignTransaction(cs consensus.State, txn *types.Transaction, toSign []types.Hash256, cf types.CoveredFields) error
	}

	// A TPool manages transactions
	TPool interface {
		RecommendedFee() types.Currency
	}

	// A Session is an RHP2 session with a host
	Session struct {
		hostKey types.PublicKey
		cm      ChainManager
		w       Wallet
		tp      TPool
		t       *rhp2.Transport

		settings rhp2.HostSettings
	}
)

// FormContract forms a new contract with the host.
func (s *Session) FormContract(hostAddr types.Address, renterKey types.PrivateKey, renterPayout, hostCollateral types.Currency, expirationHeight uint64) (rhp2.ContractRevision, []types.Transaction, error) {
	state := s.cm.TipState()
	if expirationHeight <= state.Index.Height {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("contract expiration height %v has already passed", expirationHeight)
	}

	settings, err := s.ScanSettings()
	if err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to scan settings: %w", err)
	}

	contract := rhp2.PrepareContractFormation(renterKey.PublicKey(), s.hostKey, renterPayout, hostCollateral, expirationHeight, settings, s.w.Address())
	formationCost := rhp2.ContractFormationCost(state, contract, settings.ContractPrice)
	feeEstimate := s.tp.RecommendedFee().Mul64(2000)
	formationTxn := types.Transaction{
		MinerFees:     []types.Currency{feeEstimate},
		FileContracts: []types.FileContract{contract},
	}
	fundAmount := formationCost.Add(feeEstimate)

	toSign, release, err := s.w.FundTransaction(&formationTxn, fundAmount)
	if err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to fund transaction: %w", err)
	}
	defer release()

	if err := s.w.SignTransaction(state, &formationTxn, toSign, explicitCoveredFields(formationTxn)); err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	s.t.SetDeadline(time.Now().Add(2 * time.Minute))
	defer s.t.SetDeadline(time.Time{})

	// strip signatures from formationTxn before sending
	renterSignatures := formationTxn.Signatures
	formationTxn.Signatures = nil

	// write the formation request
	renterPubkey := renterKey.PublicKey()
	req := &rhp2.RPCFormContractRequest{
		Transactions: []types.Transaction{formationTxn},
		RenterKey:    renterPubkey.UnlockKey(),
	}
	if err := s.t.WriteRequest(rhp2.RPCFormContractID, req); err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to write formation request: %w", err)
	}

	// read the host's additions
	var resp rhp2.RPCFormContractAdditions
	if err := s.t.ReadResponse(&resp, 65536); err != nil {
		return rhp2.ContractRevision{}, nil, err
	}
	// merge the additions into the formation transaction
	parents := resp.Parents
	formationTxn.SiacoinInputs = append(formationTxn.SiacoinInputs, resp.Inputs...)
	formationTxn.SiacoinOutputs = append(formationTxn.SiacoinOutputs, resp.Outputs...)

	// create a no-op revision and sign it
	initRevision := types.FileContractRevision{
		ParentID: formationTxn.FileContractID(0),
		UnlockConditions: types.UnlockConditions{
			PublicKeys: []types.UnlockKey{
				renterPubkey.UnlockKey(),
				s.hostKey.UnlockKey(),
			},
			SignaturesRequired: 2,
		},
		FileContract: types.FileContract{
			RevisionNumber:     1,
			Filesize:           contract.Filesize,
			FileMerkleRoot:     contract.FileMerkleRoot,
			WindowStart:        contract.WindowStart,
			WindowEnd:          contract.WindowEnd,
			ValidProofOutputs:  contract.ValidProofOutputs,
			MissedProofOutputs: contract.MissedProofOutputs,
			UnlockHash:         contract.UnlockHash,
		},
	}
	sigHash := hashRevision(initRevision)
	renterSig := renterKey.SignHash(sigHash)

	// write the renter signatures
	renterSigsResp := &rhp2.RPCFormContractSignatures{
		ContractSignatures: renterSignatures,
		RevisionSignature: types.TransactionSignature{
			ParentID:       types.Hash256(initRevision.ParentID),
			CoveredFields:  types.CoveredFields{FileContractRevisions: []uint64{0}},
			PublicKeyIndex: 0,
			Signature:      renterSig[:],
		},
	}
	if err := s.t.WriteResponse(renterSigsResp); err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to write renter signatures: %w", err)
	}

	// read the host's signatures
	var hostSigsResp rhp2.RPCFormContractSignatures
	if err := s.t.ReadResponse(&hostSigsResp, defaultMaxMessageSize); err != nil {
		return rhp2.ContractRevision{}, nil, fmt.Errorf("failed to read host signatures: %w", err)
	}
	// verify the host revision signature
	var hostSig types.Signature
	copy(hostSig[:], hostSigsResp.RevisionSignature.Signature[:])
	if !s.hostKey.VerifyHash(sigHash, hostSig) {
		return rhp2.ContractRevision{}, nil, errors.New("host returned an invalid signature")
	}
	formationTxn.Signatures = append(renterSignatures, hostSigsResp.ContractSignatures...)

	return rhp2.ContractRevision{
		Revision: initRevision,
		Signatures: [2]types.TransactionSignature{
			renterSigsResp.RevisionSignature,
			hostSigsResp.RevisionSignature,
		},
	}, append(parents, formationTxn), nil
}

// ScanSettings scans the host's settings and returns them.
func (s *Session) ScanSettings() (settings rhp2.HostSettings, err error) {
	s.t.SetDeadline(time.Now().Add(30 * time.Second))
	defer s.t.SetDeadline(time.Time{})
	if err := s.t.WriteRequest(rhp2.RPCSettingsID, nil); err != nil {
		return rhp2.HostSettings{}, fmt.Errorf("failed to send settings request: %w", err)
	}
	var settingsResp rhp2.RPCSettingsResponse
	if err := s.t.ReadResponse(&settingsResp, defaultMaxMessageSize); err != nil {
		return rhp2.HostSettings{}, fmt.Errorf("failed to read settings response: %w", err)
	} else if err := json.Unmarshal(settingsResp.Settings, &settings); err != nil {
		return rhp2.HostSettings{}, fmt.Errorf("failed to unmarshal settings: %w", err)
	}
	s.settings = settings
	return
}

// Close closes the underlying connection.
func (s *Session) Close() error {
	return s.t.Close()
}

// hashRevision is a helper function to hash a contract revision for signing.
func hashRevision(rev types.FileContractRevision) types.Hash256 {
	h := types.NewHasher()
	rev.EncodeTo(h.E)
	return h.Sum()
}

// explicitCoveredFields returns a CoveredFields that covers all elements
// present in txn.
func explicitCoveredFields(txn types.Transaction) (cf types.CoveredFields) {
	for i := range txn.SiacoinInputs {
		cf.SiacoinInputs = append(cf.SiacoinInputs, uint64(i))
	}
	for i := range txn.SiacoinOutputs {
		cf.SiacoinOutputs = append(cf.SiacoinOutputs, uint64(i))
	}
	for i := range txn.FileContracts {
		cf.FileContracts = append(cf.FileContracts, uint64(i))
	}
	for i := range txn.FileContractRevisions {
		cf.FileContractRevisions = append(cf.FileContractRevisions, uint64(i))
	}
	for i := range txn.StorageProofs {
		cf.StorageProofs = append(cf.StorageProofs, uint64(i))
	}
	for i := range txn.SiafundInputs {
		cf.SiafundInputs = append(cf.SiafundInputs, uint64(i))
	}
	for i := range txn.SiafundOutputs {
		cf.SiafundOutputs = append(cf.SiafundOutputs, uint64(i))
	}
	for i := range txn.MinerFees {
		cf.MinerFees = append(cf.MinerFees, uint64(i))
	}
	for i := range txn.ArbitraryData {
		cf.ArbitraryData = append(cf.ArbitraryData, uint64(i))
	}
	for i := range txn.Signatures {
		cf.Signatures = append(cf.Signatures, uint64(i))
	}
	return
}

// NewSession creates a new RHP2 session with a host. It is not safe for
// concurrent use.
func NewSession(ctx context.Context, hostKey types.PublicKey, hostAddr string, cm ChainManager, tp TPool, w Wallet) (*Session, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", hostAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial host: %w", err)
	}
	t, err := rhp2.NewRenterTransport(conn, hostKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	return &Session{
		hostKey: hostKey,
		t:       t,
		cm:      cm,
		tp:      tp,
		w:       w,
	}, nil
}
