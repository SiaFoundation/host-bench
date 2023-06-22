package benchmark

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"go.sia.tech/core/consensus"
	rhp2 "go.sia.tech/core/rhp/v2"
	rhp3 "go.sia.tech/core/rhp/v3"
	"go.sia.tech/core/types"
	proto2 "go.sia.tech/host-bench/rhp/v2"
	proto3 "go.sia.tech/host-bench/rhp/v3"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

type (
	// A ChainManager provides access to the current consensus state.
	ChainManager interface {
		// TipState returns the current consensus state.
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

	// A Manager performs benchmarks and manages contracts
	Manager struct {
		privKey types.PrivateKey

		log    *zap.Logger
		chain  ChainManager
		tpool  TPool
		wallet Wallet
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
		Error        error          `json:"error,omitempty"`
	}

	uploadResult struct {
		Roots   []types.Hash256
		Cost    types.Currency
		Elapsed time.Duration
		P99     time.Duration
	}

	downloadResult struct {
		Sectors uint64
		Cost    types.Currency
		Elapsed time.Duration
		P99     time.Duration
	}
)

// downloadBenchmark benchmarks the host's download performance.
func (m *Manager) downloadBenchmark(session *proto3.Session, pt rhp3.HostPriceTable, revision *rhp2.ContractRevision, roots []types.Hash256) (result downloadResult, _ error) {
	budget, _ := pt.ReadSectorCost(rhp2.SectorSize).Add(pt.BaseCost()).Total()
	budget = budget.Mul64(125).Div64(100)
	account := rhp3.Account(m.privKey.PublicKey())

	payment := proto3.ContractPayment(revision, m.privKey, account)
	totalCost := budget.Mul64(uint64(len(roots)))
	balance, err := session.FundAccount(account, payment, totalCost)
	if err != nil {
		return downloadResult{}, fmt.Errorf("failed to fund account: %w", err)
	}
	m.log.Debug("funded account", zap.Stringer("balance", balance))

	payment = proto3.AccountPayment(account, m.privKey)
	var readTimes []time.Duration
	for _, root := range roots {
		elapsed, cost, err := downloadSector(session, pt, revision, root, m.privKey, budget, payment)
		if err != nil {
			return downloadResult{}, fmt.Errorf("failed to download sector %v: %w", root, err)
		}
		m.log.Debug("downloaded sector", zap.Duration("elapsed", elapsed), zap.String("cost", cost.String()))
		readTimes = append(readTimes, elapsed)
		result.Elapsed += elapsed
		result.Cost = result.Cost.Add(cost)
		result.Sectors++
	}
	// calculate the p99 append time
	sort.SliceStable(readTimes, func(i, j int) bool {
		return readTimes[i] < readTimes[j]
	})
	result.P99 = readTimes[len(readTimes)*99/100]
	return
}

// uploadBenchmark benchmarks the host's upload performance.
func (m *Manager) uploadBenchmark(session *proto3.Session, pt rhp3.HostPriceTable, revision *rhp2.ContractRevision, sectors uint64) (result uploadResult, _ error) {
	usage := pt.AppendSectorCost(revision.Revision.WindowEnd - pt.HostBlockHeight)
	budget, _ := usage.Add(pt.BaseCost()).Total()
	budget = budget.Mul64(125).Div64(100)
	account := rhp3.Account(m.privKey.PublicKey())

	payment := proto3.ContractPayment(revision, m.privKey, account)

	totalCost := budget.Mul64(sectors)
	balance, err := session.FundAccount(account, payment, totalCost)
	if err != nil {
		return uploadResult{}, fmt.Errorf("failed to fund account: %w", err)
	}
	m.log.Debug("funded account", zap.Stringer("balance", balance))

	payment = proto3.AccountPayment(account, m.privKey)
	var appendTimes []time.Duration
	for i := uint64(0); i < sectors; i++ {
		root, elapsed, cost, err := appendRandomSector(session, pt, revision, m.privKey, budget, payment)
		if err != nil {
			return uploadResult{}, fmt.Errorf("failed to upload sector %d: %w", i, err)
		}
		m.log.Debug("uploaded sector", zap.Duration("elapsed", elapsed), zap.String("cost", cost.String()))
		appendTimes = append(appendTimes, elapsed)
		result.Elapsed += elapsed
		result.Cost = result.Cost.Add(cost)
		result.Roots = append(result.Roots, root)
	}
	// calculate the p99 append time
	sort.SliceStable(appendTimes, func(i, j int) bool {
		return appendTimes[i] < appendTimes[j]
	})
	result.P99 = appendTimes[len(appendTimes)*99/100]
	return
}

// BenchmarkHost benchmarks the host uploading and downloading the specified
// number of sectors.
func (m *Manager) BenchmarkHost(ctx context.Context, hostAddr string, hostKey types.PublicKey, sectors uint64) (res Result, _ error) {
	log := m.log.Named("benchmark").With(zap.String("host", hostAddr), zap.Uint64("sectors", sectors), zap.Stringer("hostKey", hostKey))
	log.Debug("opening RHP2 session")
	rhp2Session, err := proto2.NewSession(ctx, hostKey, hostAddr, m.chain, m.tpool, m.wallet)
	if err != nil {
		return Result{}, fmt.Errorf("failed to create session: %w", err)
	}
	defer rhp2Session.Close()

	log.Debug("scanning settings")

	settings, err := rhp2Session.ScanSettings()
	if err != nil {
		return Result{}, fmt.Errorf("failed to scan settings: %w", err)
	}

	log.Debug("starting RHP3 session")

	// start the RHP3 session
	handshakeStart := time.Now()
	host, _, err := net.SplitHostPort(hostAddr)
	if err != nil {
		return Result{}, fmt.Errorf("failed to split host and port: %w", err)
	}
	rhp3Addr := net.JoinHostPort(host, settings.SiaMuxPort)
	rhp3Session, err := proto3.NewSession(ctx, hostKey, rhp3Addr, m.chain, m.wallet)
	if err != nil {
		return Result{}, fmt.Errorf("failed to create session: %w", err)
	}
	res.Handshake = time.Since(handshakeStart)
	defer rhp3Session.Close()

	log.Debug("scanning price table")

	pt, err := rhp3Session.ScanPriceTable()
	if err != nil {
		return Result{}, fmt.Errorf("failed to scan price table: %w", err)
	}
	log.Debug("got price table", zap.Stringer("storagePrice", pt.WriteStoreCost), zap.Stringer("ingressPrice", pt.UploadBandwidthCost), zap.Stringer("egressPrice", pt.DownloadBandwidthCost))

	currentHeight := m.chain.TipState().Index.Height
	if pt.HostBlockHeight < currentHeight-6 {
		return Result{}, fmt.Errorf("host is not synced: %d < %d", pt.HostBlockHeight, currentHeight)
	}

	duration := uint64(300)
	uploadCost, hostCollateral := pt.AppendSectorCost(duration).Add(pt.BaseCost()).Total()
	downloadCost, _ := pt.ReadSectorCost(rhp2.SectorSize).Add(pt.BaseCost()).Total()
	log.Debug("calculated costs", zap.Stringer("uploadCost", uploadCost), zap.Stringer("hostCollateral", hostCollateral), zap.Stringer("downloadCost", downloadCost), zap.Uint64("duration", duration))

	uploadCost = uploadCost.Mul64(sectors)
	hostCollateral = hostCollateral.Mul64(sectors)
	downloadCost = downloadCost.Mul64(sectors)
	renterPayout := uploadCost.Add(downloadCost).Mul64(2)

	log.Debug("forming contract", zap.Stringer("hostCollateral", hostCollateral), zap.Stringer("renterPayout", renterPayout))

	contract, _, err := rhp2Session.FormContract(settings.Address, m.privKey, renterPayout, hostCollateral, currentHeight+duration)
	if err != nil {
		return Result{}, fmt.Errorf("failed to form contract: %w", err)
	}

	log.Info("formed contract", zap.String("contractID", contract.ID().String()), zap.Uint64("expiration", currentHeight+duration), zap.String("renterPayout", renterPayout.String()), zap.String("hostCollateral", hostCollateral.String()))

	account := rhp3.Account(m.privKey.PublicKey())
	payment := proto3.ContractPayment(&contract, m.privKey, account)

	// register a price table
	pt, err = rhp3Session.RegisterPriceTable(payment)
	if err != nil {
		return Result{}, fmt.Errorf("failed to register price table: %w", err)
	}

	// upload the sectors
	uploadResult, err := m.uploadBenchmark(rhp3Session, pt, &contract, sectors)
	if err != nil {
		return Result{}, fmt.Errorf("failed to upload sectors: %w", err)
	}
	res.Upload = uploadResult.Elapsed
	res.AppendP99 = uploadResult.P99
	res.UploadCost = uploadResult.Cost
	log.Info("upload benchmark complete", zap.Duration("elapsed", uploadResult.Elapsed), zap.Duration("p99", uploadResult.P99), zap.Stringer("cost", uploadResult.Cost))

	// download the sectors
	downloadResult, err := m.downloadBenchmark(rhp3Session, pt, &contract, uploadResult.Roots)
	if err != nil {
		return Result{}, fmt.Errorf("failed to download sectors: %w", err)
	}
	res.Download = downloadResult.Elapsed
	res.ReadP99 = downloadResult.P99
	res.DownloadCost = downloadResult.Cost
	res.Sectors = sectors
	log.Info("download benchmark complete", zap.Duration("elapsed", downloadResult.Elapsed), zap.Duration("p99", downloadResult.P99), zap.Stringer("cost", downloadResult.Cost))
	return
}

func appendRandomSector(session *proto3.Session, pt rhp3.HostPriceTable, revision *rhp2.ContractRevision, renterKey types.PrivateKey, budget types.Currency, payment proto3.PaymentMethod) (types.Hash256, time.Duration, types.Currency, error) {
	var sector [rhp2.SectorSize]byte
	frand.Read(sector[:256])

	rpcStart := time.Now()
	cost, err := session.AppendSector(&sector, revision, renterKey, payment, budget)
	if err != nil {
		return types.Hash256{}, 0, types.ZeroCurrency, fmt.Errorf("failed to append sector: %w", err)
	}
	elapsed := time.Since(rpcStart)
	return rhp2.SectorRoot(&sector), elapsed, cost, nil
}

func downloadSector(session *proto3.Session, pt rhp3.HostPriceTable, revision *rhp2.ContractRevision, root types.Hash256, renterKey types.PrivateKey, budget types.Currency, payment proto3.PaymentMethod) (time.Duration, types.Currency, error) {
	rpcStart := time.Now()
	buf, cost, err := session.ReadSector(root, 0, rhp2.SectorSize, payment, budget)
	if err != nil {
		return 0, types.ZeroCurrency, fmt.Errorf("failed to read sector: %w", err)
	}
	elapsed := time.Since(rpcStart)
	if len(buf) != rhp2.SectorSize {
		return 0, types.ZeroCurrency, fmt.Errorf("read %d bytes instead of %d", len(buf), rhp2.SectorSize)
	} else if rhp2.SectorRoot((*[rhp2.SectorSize]byte)(buf)) != root {
		return 0, types.ZeroCurrency, fmt.Errorf("read sector has wrong root")
	}
	return elapsed, cost, nil
}

// New creates a new benchmark manager.
func New(privKey types.PrivateKey, cm ChainManager, tp TPool, w Wallet, log *zap.Logger) *Manager {
	return &Manager{
		privKey: privKey,
		chain:   cm,
		tpool:   tp,
		wallet:  w,
		log:     log,
	}
}
