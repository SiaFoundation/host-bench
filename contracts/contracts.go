package contracts

import (
	"errors"
	"fmt"
	"sync"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/host-bench/internal/threadgroup"
	"go.sia.tech/siad/modules"
	"go.uber.org/zap"
)

var (
	ErrExpired  = errors.New("contract has expired")
	ErrNotFound = errors.New("contract not found")
)

type (
	Store interface {
		// AddContract adds a contract to the store.
		AddContract(types.FileContractRevision) error

		// HostContract returns an active contract for the given host key.
		HostContract(types.PublicKey) (types.FileContractID, error)
		// ExpireContracts removes contracts that are past their usable height.
		ExpireContracts(height uint64) error
	}

	ChainManager interface {
		TipState() consensus.State
		Subscribe(modules.ConsensusSetSubscriber, modules.ConsensusChangeID, <-chan struct{}) error
	}

	ContractManager struct {
		priv types.PrivateKey

		log   *zap.Logger
		store Store
		tg    threadgroup.ThreadGroup

		mu    sync.Mutex
		locks map[types.FileContractID]*sync.Mutex
	}
)

// Lock locks a contract for the given host. The returned unlock function must
// be called when the contract should no longer be locked.
func (cm *ContractManager) Lock(hostKey types.PublicKey) (types.FileContractID, func(), error) {
	done, err := cm.tg.Add()
	if err != nil {
		return types.FileContractID{}, nil, err
	}
	defer done()

	// get the contract id for the host
	contractID, err := cm.store.HostContract(hostKey)
	if err != nil {
		return types.FileContractID{}, nil, err
	}

	// check if the contract is locked
	cm.mu.Lock()
	lock, ok := cm.locks[contractID]
	if !ok {
		lock = new(sync.Mutex)
		cm.locks[contractID] = lock
	}
	cm.mu.Unlock()

	lock.Lock()
	return contractID, lock.Unlock, nil
}

// Add adds a contract to the manager.
func (cm *ContractManager) Add(revision types.FileContractRevision, cost types.Currency) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return nil
}

// Revise revises a contract.
func (cm *ContractManager) Revise(revision types.FileContractRevision, spent types.Currency) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return nil
}

// ProcessConsensusChange is called when the consensus set changes. It removes
// contracts that are past their usable height.
func (cm *ContractManager) ProcessConsensusChange(cc modules.ConsensusChange) {
	done, err := cm.tg.Add()
	if err != nil {
		return
	}
	defer done()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if err := cm.store.ExpireContracts(uint64(cc.BlockHeight)); err != nil {
		cm.log.Error("failed to expire contracts", zap.Error(err))
	}
}

// Close closes the contract manager.
func (cm *ContractManager) Close() error {
	cm.tg.Stop()
	return nil
}

// New creates a new contract manager.
func New(priv types.PrivateKey, c ChainManager, store Store, log *zap.Logger) (*ContractManager, error) {
	state := c.TipState()
	if err := store.ExpireContracts(uint64(state.Index.Height)); err != nil {
		return nil, fmt.Errorf("failed to expire contracts: %w", err)
	}
	cm := &ContractManager{
		priv:  priv,
		log:   log,
		store: store,

		locks: make(map[types.FileContractID]*sync.Mutex),
	}
	if err := c.Subscribe(cm, modules.ConsensusChangeRecent, cm.tg.Done()); err != nil {
		return nil, fmt.Errorf("failed to subscribe to consensus set: %w", err)
	}
	return cm, nil
}
