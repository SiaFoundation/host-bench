package benchmark

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.sia.tech/core/consensus"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	rhp4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/rhp/v4/siamux"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

type (
	// A ChainManager provides access to the current consensus state.
	ChainManager interface {
		TipState() consensus.State
		V2TransactionSet(basis types.ChainIndex, txn types.V2Transaction) (types.ChainIndex, []types.V2Transaction, error)
	}

	// A Wallet funds and signs v2 transactions.
	Wallet interface {
		Address() types.Address
		FundV2Transaction(txn *types.V2Transaction, amount types.Currency, useUnconfirmed bool) (types.ChainIndex, []int, error)
		BroadcastV2TransactionSet(index types.ChainIndex, txns []types.V2Transaction) error
		RecommendedFee() types.Currency
		ReleaseInputs(txns []types.Transaction, v2txns []types.V2Transaction)
		SignV2Inputs(txn *types.V2Transaction, toSign []int)
	}

	// A Manager performs benchmarks and manages contracts.
	Manager struct {
		privKey types.PrivateKey

		log    *zap.Logger
		chain  ChainManager
		wallet Wallet
	}

	// Settings contains the RHP4 settings scanned from a host.
	Settings struct {
		Settings proto4.HostSettings `json:"settings"`
	}

	// A Result contains the results of a benchmark.
	Result struct {
		Sectors      uint64         `json:"sectors"`
		Handshake    time.Duration  `json:"handshake"`
		AppendP99    time.Duration  `json:"appendP99"`
		ReadP99      time.Duration  `json:"readP99"`
		Upload       time.Duration  `json:"upload"`
		Download     time.Duration  `json:"download"`
		UploadCost   types.Currency `json:"uploadCost"`
		DownloadCost types.Currency `json:"downloadCost"`
	}

	formContractSigner struct {
		privKey types.PrivateKey
		wallet  Wallet
	}

	uploadResult struct {
		Roots    []types.Hash256
		Cost     types.Currency
		Revision types.V2FileContract
		Elapsed  time.Duration
		P99      time.Duration
	}

	downloadResult struct {
		Sectors uint64
		Cost    types.Currency
		Elapsed time.Duration
		P99     time.Duration
	}
)

func (s formContractSigner) FundV2Transaction(txn *types.V2Transaction, amount types.Currency) (types.ChainIndex, []int, error) {
	return s.wallet.FundV2Transaction(txn, amount, false)
}

func (s formContractSigner) RecommendedFee() types.Currency {
	return s.wallet.RecommendedFee()
}

func (s formContractSigner) ReleaseInputs(txns []types.V2Transaction) {
	s.wallet.ReleaseInputs(nil, txns)
}

func (s formContractSigner) SignHash(h types.Hash256) types.Signature {
	return s.privKey.SignHash(h)
}

func (s formContractSigner) SignV2Inputs(txn *types.V2Transaction, toSign []int) {
	s.wallet.SignV2Inputs(txn, toSign)
}

func dialRHP4(ctx context.Context, hostAddr string, hostKey types.PublicKey) (rhp4.TransportClient, time.Duration, error) {
	start := time.Now()
	transport, err := siamux.Dial(ctx, hostAddr, hostKey)
	return transport, time.Since(start), err
}

func contractDuration(currentHeight uint64, prices proto4.HostPrices, settings proto4.HostSettings) (duration, proofHeight, priceDuration uint64, err error) {
	duration = max(300, proto4.MinContractDuration)
	if settings.MaxContractDuration != 0 && duration > settings.MaxContractDuration {
		duration = settings.MaxContractDuration
	}
	if duration < proto4.MinContractDuration {
		return 0, 0, 0, fmt.Errorf("host max contract duration %d is less than minimum %d", settings.MaxContractDuration, uint64(proto4.MinContractDuration))
	}
	proofHeight = currentHeight + duration
	if proofHeight <= prices.TipHeight {
		priceDuration = duration
	} else {
		priceDuration = proofHeight - prices.TipHeight
	}
	return
}

func benchmarkCosts(prices proto4.HostPrices, sectors, duration uint64) (writeUsage, appendUsage, readUsage proto4.Usage, accountFundAmount, renterAllowance, hostCollateral types.Currency) {
	writeUsage = prices.RPCWriteSectorCost(proto4.SectorSize).Mul(sectors)
	appendUsage = prices.RPCAppendSectorsCost(sectors, duration)
	readUsage = prices.RPCReadSectorCost(proto4.SectorSize).Mul(sectors)

	accountFundAmount = writeUsage.RenterCost().Add(readUsage.RenterCost()).Mul64(125).Div64(100)
	renterAllowance = accountFundAmount.Add(appendUsage.RenterCost()).Mul64(125).Div64(100)
	hostCollateral = appendUsage.HostRiskedCollateral()
	return
}

// ScanHost scans the host at the given address and returns the RHP4 settings.
func (m *Manager) ScanHost(ctx context.Context, hostAddr string, hostKey types.PublicKey) (Settings, error) {
	log := m.log.Named("scan").With(zap.String("host", hostAddr), zap.Stringer("hostKey", hostKey))
	log.Debug("opening RHP4 siamux transport")
	transport, _, err := dialRHP4(ctx, hostAddr, hostKey)
	if err != nil {
		return Settings{}, fmt.Errorf("failed to connect to host: %w", err)
	}
	defer transport.Close()

	log.Debug("scanning RHP4 settings")
	settings, err := rhp4.RPCSettings(ctx, transport)
	if err != nil {
		return Settings{}, fmt.Errorf("failed to scan settings: %w", err)
	}
	log.Debug("got RHP4 settings",
		zap.String("release", settings.Release),
		zap.Uint64("tipHeight", settings.Prices.TipHeight),
		zap.Stringer("storagePrice", settings.Prices.StoragePrice),
		zap.Stringer("ingressPrice", settings.Prices.IngressPrice),
		zap.Stringer("egressPrice", settings.Prices.EgressPrice))
	return Settings{Settings: settings}, nil
}

// BenchmarkHost benchmarks the host uploading and downloading the specified
// number of sectors.
func (m *Manager) BenchmarkHost(ctx context.Context, hostAddr string, hostKey types.PublicKey, sectors uint64) (res Result, _ error) {
	if sectors == 0 {
		return Result{}, errors.New("sectors must be greater than zero")
	}

	log := m.log.Named("benchmark").With(zap.String("host", hostAddr), zap.Uint64("sectors", sectors), zap.Stringer("hostKey", hostKey))
	log.Debug("opening RHP4 siamux transport")
	transport, handshake, err := dialRHP4(ctx, hostAddr, hostKey)
	if err != nil {
		return Result{}, fmt.Errorf("failed to connect to host: %w", err)
	}
	res.Handshake = handshake
	defer transport.Close()

	log.Debug("scanning RHP4 settings")
	settings, err := rhp4.RPCSettings(ctx, transport)
	if err != nil {
		return Result{}, fmt.Errorf("failed to scan settings: %w", err)
	} else if !settings.AcceptingContracts {
		return Result{}, fmt.Errorf("host is not accepting contracts")
	} else if settings.RemainingStorage < sectors {
		return Result{}, fmt.Errorf("host has insufficient storage: %d < %d sectors", settings.RemainingStorage, sectors)
	}
	prices := settings.Prices
	log.Debug("got RHP4 settings", zap.String("release", settings.Release), zap.Uint64("tipHeight", prices.TipHeight))

	cs := m.chain.TipState()
	currentHeight := cs.Index.Height
	if currentHeight > 6 && prices.TipHeight+6 < currentHeight {
		return Result{}, fmt.Errorf("host is not synced: %d < %d", prices.TipHeight, currentHeight)
	}

	duration, proofHeight, priceDuration, err := contractDuration(currentHeight, prices, settings)
	if err != nil {
		return Result{}, err
	}
	writeUsage, appendUsage, readUsage, accountFundAmount, renterAllowance, hostCollateral := benchmarkCosts(prices, sectors, priceDuration)
	if hostCollateral.Cmp(settings.MaxCollateral) > 0 {
		return Result{}, fmt.Errorf("host collateral exceeds maximum: %s > %s", hostCollateral, settings.MaxCollateral)
	}
	log.Debug("calculated costs",
		zap.Stringer("accountFunding", accountFundAmount),
		zap.Stringer("renterAllowance", renterAllowance),
		zap.Stringer("hostCollateral", hostCollateral),
		zap.Stringer("writeCost", writeUsage.RenterCost()),
		zap.Stringer("appendCost", appendUsage.RenterCost()),
		zap.Stringer("readCost", readUsage.RenterCost()),
		zap.Uint64("duration", duration),
		zap.Uint64("proofHeight", proofHeight))

	signer := formContractSigner{privKey: m.privKey, wallet: m.wallet}
	log.Debug("forming RHP4 contract")
	form, err := rhp4.RPCFormContract(ctx, transport, m.chain, signer, cs, prices, hostKey, settings.WalletAddress, proto4.RPCFormContractParams{
		RenterPublicKey: m.privKey.PublicKey(),
		RenterAddress:   m.wallet.Address(),
		Allowance:       renterAllowance,
		Collateral:      hostCollateral,
		ProofHeight:     proofHeight,
	})
	if err != nil {
		return Result{}, fmt.Errorf("failed to form contract: %w", err)
	}
	if err := m.wallet.BroadcastV2TransactionSet(form.FormationSet.Basis, form.FormationSet.Transactions); err != nil {
		signer.ReleaseInputs(form.FormationSet.Transactions)
		return Result{}, fmt.Errorf("failed to broadcast formation set: %w", err)
	}
	contract := form.Contract
	log.Info("formed contract", zap.Stringer("contractID", contract.ID), zap.Uint64("expiration", contract.Revision.ExpirationHeight), zap.Stringer("renterAllowance", renterAllowance), zap.Stringer("hostCollateral", hostCollateral))

	if !accountFundAmount.IsZero() {
		account := proto4.Account(m.privKey.PublicKey())
		fund, err := rhp4.RPCFundAccounts(ctx, transport, cs, m.privKey, contract, []proto4.AccountDeposit{
			{Account: account, Amount: accountFundAmount},
		})
		if err != nil {
			return Result{}, fmt.Errorf("failed to fund RHP4 account: %w", err)
		}
		contract.Revision = fund.Revision
		log.Debug("funded RHP4 account", zap.Stringer("account", types.PublicKey(account)), zap.Stringer("amount", accountFundAmount))
	}

	uploadResult, err := m.uploadBenchmark(ctx, transport, prices, contract, hostKey, sectors)
	if err != nil {
		return Result{}, fmt.Errorf("failed to upload sectors: %w", err)
	}
	contract.Revision = uploadResult.Revision
	res.Upload = uploadResult.Elapsed
	res.AppendP99 = uploadResult.P99
	res.UploadCost = uploadResult.Cost
	log.Info("upload benchmark complete", zap.Duration("elapsed", uploadResult.Elapsed), zap.Duration("p99", uploadResult.P99), zap.Stringer("cost", uploadResult.Cost))

	downloadResult, err := m.downloadBenchmark(ctx, transport, prices, hostKey, uploadResult.Roots)
	if err != nil {
		return Result{}, fmt.Errorf("failed to download sectors: %w", err)
	}
	res.Download = downloadResult.Elapsed
	res.ReadP99 = downloadResult.P99
	res.DownloadCost = downloadResult.Cost
	res.Sectors = sectors
	log.Info("download benchmark complete", zap.Duration("elapsed", downloadResult.Elapsed), zap.Duration("p99", downloadResult.P99), zap.Stringer("cost", downloadResult.Cost))
	return res, nil
}

func (m *Manager) uploadBenchmark(ctx context.Context, transport rhp4.TransportClient, prices proto4.HostPrices, contract rhp4.ContractRevision, hostKey types.PublicKey, sectors uint64) (result uploadResult, _ error) {
	token := proto4.NewAccountToken(m.privKey, hostKey)

	var appendTimes []time.Duration
	for i := range sectors {
		root, revision, elapsed, cost, err := m.uploadRandomSector(ctx, transport, prices, contract, token)
		if err != nil {
			return uploadResult{}, fmt.Errorf("failed to upload sector %d: %w", i, err)
		}
		contract.Revision = revision
		appendTimes = append(appendTimes, elapsed)
		result.Elapsed += elapsed
		result.Cost = result.Cost.Add(cost)
		result.Roots = append(result.Roots, root)
		m.log.Debug("uploaded sector", zap.Uint64("sector", i), zap.Duration("elapsed", elapsed), zap.Stringer("cost", cost))
	}
	sort.SliceStable(appendTimes, func(i, j int) bool {
		return appendTimes[i] < appendTimes[j]
	})
	result.P99 = appendTimes[len(appendTimes)*99/100]
	result.Revision = contract.Revision
	return
}

func (m *Manager) uploadRandomSector(ctx context.Context, transport rhp4.TransportClient, prices proto4.HostPrices, contract rhp4.ContractRevision, token proto4.AccountToken) (types.Hash256, types.V2FileContract, time.Duration, types.Currency, error) {
	var sector [proto4.SectorSize]byte
	frand.Read(sector[:])

	rpcStart := time.Now()
	write, err := rhp4.RPCWriteSector(ctx, transport, prices, token, bytes.NewReader(sector[:]), proto4.SectorSize)
	if err != nil {
		return types.Hash256{}, types.V2FileContract{}, 0, types.ZeroCurrency, fmt.Errorf("failed to write sector: %w", err)
	} else if write.Root != proto4.SectorRoot(&sector) {
		return types.Hash256{}, types.V2FileContract{}, 0, types.ZeroCurrency, fmt.Errorf("write sector returned wrong root")
	}
	appendResult, err := rhp4.RPCAppendSectors(ctx, transport, m.privKey, m.chain.TipState(), prices, contract, []types.Hash256{write.Root})
	if err != nil {
		return types.Hash256{}, types.V2FileContract{}, 0, types.ZeroCurrency, fmt.Errorf("failed to append sector: %w", err)
	}
	elapsed := time.Since(rpcStart)
	cost := write.Usage.RenterCost().Add(appendResult.Usage.RenterCost())
	return write.Root, appendResult.Revision, elapsed, cost, nil
}

func (m *Manager) downloadBenchmark(ctx context.Context, transport rhp4.TransportClient, prices proto4.HostPrices, hostKey types.PublicKey, roots []types.Hash256) (result downloadResult, _ error) {
	token := proto4.NewAccountToken(m.privKey, hostKey)

	var readTimes []time.Duration
	for _, root := range roots {
		elapsed, cost, err := downloadSector(ctx, transport, prices, token, root)
		if err != nil {
			return downloadResult{}, fmt.Errorf("failed to download sector %v: %w", root, err)
		}
		readTimes = append(readTimes, elapsed)
		result.Elapsed += elapsed
		result.Cost = result.Cost.Add(cost)
		result.Sectors++
		m.log.Debug("downloaded sector", zap.Duration("elapsed", elapsed), zap.Stringer("cost", cost))
	}
	sort.SliceStable(readTimes, func(i, j int) bool {
		return readTimes[i] < readTimes[j]
	})
	result.P99 = readTimes[len(readTimes)*99/100]
	return
}

func downloadSector(ctx context.Context, transport rhp4.TransportClient, prices proto4.HostPrices, token proto4.AccountToken, root types.Hash256) (time.Duration, types.Currency, error) {
	var buf bytes.Buffer
	rpcStart := time.Now()
	read, err := rhp4.RPCReadSector(ctx, transport, prices, token, &buf, root, 0, proto4.SectorSize)
	if err != nil {
		return 0, types.ZeroCurrency, fmt.Errorf("failed to read sector: %w", err)
	}
	elapsed := time.Since(rpcStart)
	if buf.Len() != proto4.SectorSize {
		return 0, types.ZeroCurrency, fmt.Errorf("read %d bytes instead of %d", buf.Len(), proto4.SectorSize)
	}
	var sector [proto4.SectorSize]byte
	copy(sector[:], buf.Bytes())
	if proto4.SectorRoot(&sector) != root {
		return 0, types.ZeroCurrency, fmt.Errorf("read sector has wrong root")
	}
	return elapsed, read.Usage.RenterCost(), nil
}

// New creates a new benchmark manager.
func New(privKey types.PrivateKey, cm ChainManager, w Wallet, log *zap.Logger) *Manager {
	return &Manager{
		privKey: privKey,
		chain:   cm,
		wallet:  w,
		log:     log,
	}
}
