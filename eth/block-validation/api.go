package blockvalidation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

type BlacklistedAddresses []common.Address

type AccessVerifier struct {
	blacklistedAddresses map[common.Address]struct{}
}

func (a *AccessVerifier) verifyTraces(tracer *logger.AccessListTracer) error {
	log.Trace("x", "tracer.AccessList()", tracer.AccessList())
	for _, accessTuple := range tracer.AccessList() {
		// TODO: should we ignore common.Address{}?
		if _, found := a.blacklistedAddresses[accessTuple.Address]; found {
			log.Info("bundle accesses blacklisted address", "address", accessTuple.Address)
			return fmt.Errorf("blacklisted address %s in execution trace", accessTuple.Address.String())
		}
	}

	return nil
}

func (a *AccessVerifier) isBlacklisted(addr common.Address) error {
	if _, present := a.blacklistedAddresses[addr]; present {
		return fmt.Errorf("transaction from blacklisted address %s", addr.String())
	}
	return nil
}

func (a *AccessVerifier) verifyTransactions(signer types.Signer, txs types.Transactions) error {
	for _, tx := range txs {
		from, err := types.Sender(signer, tx)
		if err == nil {
			if _, present := a.blacklistedAddresses[from]; present {
				return fmt.Errorf("transaction from blacklisted address %s", from.String())
			}
		}
		to := tx.To()
		if to != nil {
			if _, present := a.blacklistedAddresses[*to]; present {
				return fmt.Errorf("transaction to blacklisted address %s", to.String())
			}
		}
	}
	return nil
}

func NewAccessVerifierFromFile(path string) (*AccessVerifier, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ba BlacklistedAddresses
	if err := json.Unmarshal(bytes, &ba); err != nil {
		return nil, err
	}

	blacklistedAddresses := make(map[common.Address]struct{}, len(ba))
	for _, address := range ba {
		blacklistedAddresses[address] = struct{}{}
	}

	return &AccessVerifier{
		blacklistedAddresses: blacklistedAddresses,
	}, nil
}

type BlockValidationConfig struct {
	BlacklistSourceFilePath string
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	UseBalanceDiffProfit bool
	// If set to true, withdrawals to the fee recipient are excluded from the balance difference.
	ExcludeWithdrawals bool
}

// Register adds catalyst APIs to the full node.
func Register(stack *node.Node, backend *eth.Ethereum, cfg BlockValidationConfig) error {
	var accessVerifier *AccessVerifier
	if cfg.BlacklistSourceFilePath != "" {
		var err error
		accessVerifier, err = NewAccessVerifierFromFile(cfg.BlacklistSourceFilePath)
		if err != nil {
			return err
		}
	}

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "flashbots",
			Service:   NewBlockValidationAPI(backend, accessVerifier, cfg.UseBalanceDiffProfit, cfg.ExcludeWithdrawals),
		},
	})
	return nil
}

type BlockValidationAPI struct {
	eth            *eth.Ethereum
	forker         *core.ForkChoice
	accessVerifier *AccessVerifier
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	useBalanceDiffProfit bool
	// If set to true, withdrawals to the fee recipient are excluded from the balance delta.
	excludeWithdrawals bool
}

// NewBlockValidationAPI creates a new block validation api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewBlockValidationAPI(eth *eth.Ethereum, accessVerifier *AccessVerifier, useBalanceDiffProfit, excludeWithdrawals bool) *BlockValidationAPI {
	shouldPreserve := func(header *types.Header) bool {
		return false
	}
	return &BlockValidationAPI{
		eth:                  eth,
		forker:               core.NewForkChoice(eth.BlockChain(), shouldPreserve),
		accessVerifier:       accessVerifier,
		useBalanceDiffProfit: useBalanceDiffProfit,
		excludeWithdrawals:   excludeWithdrawals,
	}
}

type BuilderBlockValidationRequest struct {
	builderApiBellatrix.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV1(params *BuilderBlockValidationRequest) error {
	// no longer supported endpoint
	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := ExecutionPayloadV1ToBlock(payload)
	if err != nil {
		return err
	}

	return api.validateBlock(block, params.Message, params.RegisteredGasLimit)
}

type BuilderBlockValidationRequestV2 struct {
	builderApiCapella.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequestV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit

	blockRequest := new(builderApiCapella.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV2(params *BuilderBlockValidationRequestV2) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!
	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := ExecutionPayloadV2ToBlock(payload)
	if err != nil {
		return err
	}

	return api.validateBlock(block, params.Message, params.RegisteredGasLimit)
}

type BuilderBlockValidationRequestV3 struct {
	builderApiDeneb.SubmitBlockRequest
	ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
	RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequestV3) UnmarshalJSON(data []byte) error {
	params := &struct {
		ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
		RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit
	r.ParentBeaconBlockRoot = params.ParentBeaconBlockRoot

	blockRequest := new(builderApiDeneb.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV3(params *BuilderBlockValidationRequestV3) error {
	// TODO: fuzztest, make sure the validation is sound
	payload := params.ExecutionPayload
	blobsBundle := params.BlobsBundle
	log.Info("blobs bundle", "blobs", len(blobsBundle.Blobs), "commits", len(blobsBundle.Commitments), "proofs", len(blobsBundle.Proofs))
	block, err := ExecutionPayloadV3ToBlock(payload, blobsBundle, params.ParentBeaconBlockRoot)
	if err != nil {
		return err
	}

	err = api.validateBlock(block, params.Message, params.RegisteredGasLimit)
	if err != nil {
		log.Error("invalid payload", "hash", block.Hash, "number", block.NumberU64(), "parentHash", block.ParentHash, "err", err)
		return err
	}
	err = validateBlobsBundle(block.Transactions(), blobsBundle)
	if err != nil {
		log.Error("invalid blobs bundle", "err", err)
		return err
	}
	return nil
}

func (api *BlockValidationAPI) validateBlock(block *types.Block, msg *builderApiV1.BidTrace, registeredGasLimit uint64) error {
	if msg.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", msg.ParentHash.String(), block.ParentHash().String())
	}

	if msg.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", msg.BlockHash.String(), block.Hash().String())
	}

	if msg.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", msg.GasLimit, block.GasLimit())
	}

	if msg.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", msg.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(msg.ProposerFeeRecipient[:])
	expectedProfit := msg.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(block.NumberU64()), isPostMerge, block.Time()))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer.Hooks()}
	}

	err := api.ValidatePayload(block, feeRecipient, expectedProfit, registeredGasLimit, vmconfig, api.useBalanceDiffProfit, api.excludeWithdrawals)
	if err != nil {
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}

	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}

func validateBlobsBundle(txs types.Transactions, blobsBundle *builderApiDeneb.BlobsBundle) error {
	var hashes []common.Hash
	for _, tx := range txs {
		hashes = append(hashes, tx.BlobHashes()...)
	}
	blobs := blobsBundle.Blobs
	commits := blobsBundle.Commitments
	proofs := blobsBundle.Proofs

	if len(blobs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blobs compared to %d blob hashes", len(blobs), len(hashes))
	}
	if len(commits) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob commitments compared to %d blob hashes", len(commits), len(hashes))
	}
	if len(proofs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob proofs compared to %d blob hashes", len(proofs), len(hashes))
	}

	for i := range blobs {
		blob := kzg4844.Blob(blobs[i])
		if err := kzg4844.VerifyBlobProof(&blob, kzg4844.Commitment(commits[i]), kzg4844.Proof(proofs[i])); err != nil {
			return fmt.Errorf("invalid blob %d: %v", i, err)
		}
	}
	log.Info("validated blobs bundle", "blobs", len(blobs), "commits", len(commits), "proofs", len(proofs))
	return nil
}

func ExecutionPayloadV1ToBlock(payload *bellatrix.ExecutionPayload) (*types.Block, error) {
	// base fee per gas is stored little-endian but we need it
	// big-endian for big.Int.
	var baseFeePerGasBytes [32]byte
	for i := 0; i < 32; i++ {
		baseFeePerGasBytes[i] = payload.BaseFeePerGas[32-1-i]
	}
	baseFeePerGas := new(big.Int).SetBytes(baseFeePerGasBytes[:])

	txs := make([][]byte, len(payload.Transactions))
	for i, txHexBytes := range payload.Transactions {
		txs[i] = txHexBytes
	}
	executableData := engine.ExecutableData{
		ParentHash:    common.Hash(payload.ParentHash),
		FeeRecipient:  common.Address(payload.FeeRecipient),
		StateRoot:     common.Hash(payload.StateRoot),
		ReceiptsRoot:  common.Hash(payload.ReceiptsRoot),
		LogsBloom:     payload.LogsBloom[:],
		Random:        common.Hash(payload.PrevRandao),
		Number:        payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: baseFeePerGas,
		BlockHash:     common.Hash(payload.BlockHash),
		Transactions:  txs,
	}
	return engine.ExecutableDataToBlock(executableData, nil, nil)
}

func ExecutionPayloadV2ToBlock(payload *capella.ExecutionPayload) (*types.Block, error) {
	// base fee per gas is stored little-endian but we need it
	// big-endian for big.Int.
	var baseFeePerGasBytes [32]byte
	for i := 0; i < 32; i++ {
		baseFeePerGasBytes[i] = payload.BaseFeePerGas[32-1-i]
	}
	baseFeePerGas := new(big.Int).SetBytes(baseFeePerGasBytes[:])

	txs := make([][]byte, len(payload.Transactions))
	for i, txHexBytes := range payload.Transactions {
		txs[i] = txHexBytes
	}

	withdrawals := make([]*types.Withdrawal, len(payload.Withdrawals))
	for i, withdrawal := range payload.Withdrawals {
		withdrawals[i] = &types.Withdrawal{
			Index:     uint64(withdrawal.Index),
			Validator: uint64(withdrawal.ValidatorIndex),
			Address:   common.Address(withdrawal.Address),
			Amount:    uint64(withdrawal.Amount),
		}
	}
	executableData := engine.ExecutableData{
		ParentHash:    common.Hash(payload.ParentHash),
		FeeRecipient:  common.Address(payload.FeeRecipient),
		StateRoot:     common.Hash(payload.StateRoot),
		ReceiptsRoot:  common.Hash(payload.ReceiptsRoot),
		LogsBloom:     payload.LogsBloom[:],
		Random:        common.Hash(payload.PrevRandao),
		Number:        payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: baseFeePerGas,
		BlockHash:     common.Hash(payload.BlockHash),
		Transactions:  txs,
		Withdrawals:   withdrawals,
	}
	return engine.ExecutableDataToBlock(executableData, nil, nil)
}

func ExecutionPayloadV3ToBlock(payload *deneb.ExecutionPayload, blobsBundle *builderApiDeneb.BlobsBundle, parentBeaconBlockRoot common.Hash) (*types.Block, error) {
	txs := make([][]byte, len(payload.Transactions))
	for i, txHexBytes := range payload.Transactions {
		txs[i] = txHexBytes
	}

	withdrawals := make([]*types.Withdrawal, len(payload.Withdrawals))
	for i, withdrawal := range payload.Withdrawals {
		withdrawals[i] = &types.Withdrawal{
			Index:     uint64(withdrawal.Index),
			Validator: uint64(withdrawal.ValidatorIndex),
			Address:   common.Address(withdrawal.Address),
			Amount:    uint64(withdrawal.Amount),
		}
	}

	hasher := sha256.New()
	versionedHashes := make([]common.Hash, len(blobsBundle.Commitments))
	for i, commitment := range blobsBundle.Commitments {
		c := kzg4844.Commitment(commitment)
		computed := kzg4844.CalcBlobHashV1(hasher, &c)
		versionedHashes[i] = common.Hash(computed)
	}

	executableData := engine.ExecutableData{
		ParentHash:    common.Hash(payload.ParentHash),
		FeeRecipient:  common.Address(payload.FeeRecipient),
		StateRoot:     common.Hash(payload.StateRoot),
		ReceiptsRoot:  common.Hash(payload.ReceiptsRoot),
		LogsBloom:     payload.LogsBloom[:],
		Random:        common.Hash(payload.PrevRandao),
		Number:        payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: payload.BaseFeePerGas.ToBig(),
		BlockHash:     common.Hash(payload.BlockHash),
		Transactions:  txs,
		Withdrawals:   withdrawals,
		BlobGasUsed:   &payload.BlobGasUsed,
		ExcessBlobGas: &payload.ExcessBlobGas,
	}
	return engine.ExecutableDataToBlock(executableData, versionedHashes, &parentBeaconBlockRoot)
}

// ValidatePayload validates the payload of the block.
// It returns nil if the payload is valid, otherwise it returns an error.
//   - `useBalanceDiffProfit` if set to false, proposer payment is assumed to be in the last transaction of the block
//     otherwise we use proposer balance changes after the block to calculate proposer payment (see details in the code)
//   - `excludeWithdrawals` if set to true, withdrawals to the fee recipient are excluded from the balance change
func (api *BlockValidationAPI) ValidatePayload(block *types.Block, feeRecipient common.Address, expectedProfit *big.Int, registeredGasLimit uint64, vmConfig vm.Config, useBalanceDiffProfit, excludeWithdrawals bool) error {
	header := block.Header()
	bc := api.eth.BlockChain()
	if err := bc.Engine().VerifyHeader(bc, header); err != nil {
		return err
	}

	current := bc.CurrentBlock()
	reorg, err := api.forker.ReorgNeeded(current, header)
	if err == nil && reorg {
		return errors.New("block requires a reorg")
	}

	parent := bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return errors.New("parent not found")
	}

	calculatedGasLimit := CalcGasLimit(parent.GasLimit, registeredGasLimit)
	if calculatedGasLimit != header.GasLimit {
		return errors.New("incorrect gas limit set")
	}

	statedb, err := bc.StateAt(parent.Root)
	if err != nil {
		return err
	}

	// The chain importer is starting and stopping trie prefetchers. If a bad
	// block or other error is hit however, an early return may not properly
	// terminate the background threads. This defer ensures that we clean up
	// and dangling prefetcher, without defering each and holding on live refs.
	defer statedb.StopPrefetcher()

	feeRecipientBalanceBefore := new(uint256.Int).Set(statedb.GetBalance(feeRecipient))

	receipts, _, usedGas, err := bc.Processor().Process(block, statedb, vmConfig)
	if err != nil {
		return err
	}

	feeRecipientBalanceAfter := new(uint256.Int).Set(statedb.GetBalance(feeRecipient))

	amtBeforeOrWithdrawn := new(uint256.Int).Set(feeRecipientBalanceBefore)
	if excludeWithdrawals {
		for _, w := range block.Withdrawals() {
			if w.Address == feeRecipient {
				amount := new(uint256.Int).Mul(new(uint256.Int).SetUint64(w.Amount), uint256.NewInt(params.GWei))
				amtBeforeOrWithdrawn = amtBeforeOrWithdrawn.Add(amtBeforeOrWithdrawn, amount)
			}
		}
	}

	if bc.Config().IsShanghai(header.Number, header.Time) {
		if header.WithdrawalsHash == nil {
			return fmt.Errorf("withdrawals hash is missing")
		}
		// withdrawals hash and withdrawals validated later in ValidateBody
	} else {
		if header.WithdrawalsHash != nil {
			return fmt.Errorf("withdrawals hash present before shanghai")
		}
		if block.Withdrawals() != nil {
			return fmt.Errorf("withdrawals list present in block body before shanghai")
		}
	}

	if err := bc.Validator().ValidateBody(block); err != nil {
		return err
	}

	if err := bc.Validator().ValidateState(block, statedb, receipts, usedGas, false); err != nil {
		return err
	}

	// Validate proposer payment

	if useBalanceDiffProfit && feeRecipientBalanceAfter.Cmp(amtBeforeOrWithdrawn) >= 0 {
		feeRecipientBalanceDelta := new(uint256.Int).Set(feeRecipientBalanceAfter)
		feeRecipientBalanceDelta = feeRecipientBalanceDelta.Sub(feeRecipientBalanceDelta, amtBeforeOrWithdrawn)

		uint256ExpectedProfit, ok := uint256.FromBig(expectedProfit)
		if !ok {
			if feeRecipientBalanceDelta.Cmp(uint256ExpectedProfit) >= 0 {
				if feeRecipientBalanceDelta.Cmp(uint256ExpectedProfit) > 0 {
					log.Warn("builder claimed profit is lower than calculated profit", "expected", expectedProfit, "actual", feeRecipientBalanceDelta)
				}
				return nil
			}
			log.Warn("proposer payment not enough, trying last tx payment validation", "expected", expectedProfit, "actual", feeRecipientBalanceDelta)
		}
	}

	if len(receipts) == 0 {
		return errors.New("no proposer payment receipt")
	}

	lastReceipt := receipts[len(receipts)-1]
	if lastReceipt.Status != types.ReceiptStatusSuccessful {
		return errors.New("proposer payment not successful")
	}
	txIndex := lastReceipt.TransactionIndex
	if txIndex+1 != uint(len(block.Transactions())) {
		return fmt.Errorf("proposer payment index not last transaction in the block (%d of %d)", txIndex, len(block.Transactions())-1)
	}

	paymentTx := block.Transaction(lastReceipt.TxHash)
	if paymentTx == nil {
		return errors.New("payment tx not in the block")
	}

	paymentTo := paymentTx.To()
	if paymentTo == nil || *paymentTo != feeRecipient {
		return fmt.Errorf("payment tx not to the proposers fee recipient (%v)", paymentTo)
	}

	if paymentTx.Value().Cmp(expectedProfit) != 0 {
		return fmt.Errorf("inaccurate payment %s, expected %s", paymentTx.Value().String(), expectedProfit.String())
	}

	if len(paymentTx.Data()) != 0 {
		return fmt.Errorf("malformed proposer payment, contains calldata")
	}

	if paymentTx.GasPrice().Cmp(block.BaseFee()) != 0 {
		return fmt.Errorf("malformed proposer payment, gas price not equal to base fee")
	}

	if paymentTx.GasTipCap().Cmp(block.BaseFee()) != 0 && paymentTx.GasTipCap().Sign() != 0 {
		return fmt.Errorf("malformed proposer payment, unexpected gas tip cap")
	}

	if paymentTx.GasFeeCap().Cmp(block.BaseFee()) != 0 {
		return fmt.Errorf("malformed proposer payment, unexpected gas fee cap")
	}

	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
