package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/babylonlabs-io/babylon/v2/x/finality/types"
	"fmt"
)

// TallyBlocks tries to finalise all blocks that are non-finalised AND have a non-nil
// finality provider set, from earliest to the latest.
//
// This function is invoked upon each `EndBlock` *after* the BTC staking protocol is activated
// It ensures that at height `h`, the ancestor chain `[activated_height, h-1]` contains either
// - finalised blocks (i.e., block with finality provider set AND QC of this finality provider set)
// - non-finalisable blocks (i.e., block with no active finality providers)
// but without block that has finality providers set AND does not receive QC
func (k Keeper) TallyBlocks(ctx context.Context, maxFinalizedBlocks uint64) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	activatedHeight, _ := k.GetBTCStakingActivatedHeight(ctx)
	// start finalising blocks since max(activatedHeight, nextHeightToFinalize)
	startHeight := k.getNextHeightToFinalize(ctx)
	if startHeight < activatedHeight {
		startHeight = activatedHeight
	}

	currentLastBlockHeight := uint64(sdkCtx.HeaderInfo().Height)
	k.HasBlock(ctx, currentLastBlockHeight)
	k.IndexBlock(ctx)

	// find all blocks that are non-finalised AND have finality provider set since max(activatedHeight, lastFinalizedHeight+1)
	// There are 4 different scenarios as follows
	// - has finality providers, non-finalised: tally and try to finalise
	// - does not have finality providers, non-finalised: non-finalisable, continue
	// - has finality providers, finalised: impossible to happen, panic
	// - does not have finality providers, finalised: impossible to happen, panic
	// After this for loop, the blocks since earliest activated height are either finalised or non-finalisable
	ib, _ := k.GetBlock(ctx, currentLastBlockHeight)
	// get the finality provider set of this block
	fpSet := k.GetVotingPowerTable(ctx, ib.Height)

	// has finality providers, non-finalised: tally and try to finalise the block
	voterBTCPKs := k.GetVoters(ctx, ib.Height)
	tally(fpSet, voterBTCPKs)
	// if this block gets >2/3 votes, finalise it
	k.finalizeBlock(ctx, ib)
}

// finalizeBlock sets a block to be finalised in KVStore and distributes rewards to
// finality providers and delegations
func (k Keeper) finalizeBlock(ctx context.Context, block *types.IndexedBlock) {
	// set block to be finalised in KVStore
	block.Finalized = true
	k.SetBlock(ctx, block)
	// set next height to finalise as height+1
	k.setNextHeightToFinalize(ctx, block.Height+1)
	// record the last finalized height metric
	types.RecordLastFinalizedHeight(block.Height)
	fmt.Println("finality finalizeBlock", block)
}

// tally checks whether a block with the given finality provider set and votes reaches a quorum or not
func tally(fpSet map[string]uint64, voterBTCPKs map[string]struct{}) bool {
	totalPower := uint64(0)
	votedPower := uint64(0)
	for pkStr, power := range fpSet {
		totalPower += power
		if _, ok := voterBTCPKs[pkStr]; ok {
			votedPower += power
		}
	}

	return votedPower*3 > totalPower*2
}

// setNextHeightToFinalize sets the next height to finalise as the given height
func (k Keeper) setNextHeightToFinalize(ctx context.Context, height uint64) {
	store := k.storeService.OpenKVStore(ctx)
	heightBytes := sdk.Uint64ToBigEndian(height)
	if err := store.Set(types.NextHeightToFinalizeKey, heightBytes); err != nil {
		panic(err)
	}
}

// getNextHeightToFinalize gets the next height to finalise
func (k Keeper) getNextHeightToFinalize(ctx context.Context) uint64 {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.NextHeightToFinalizeKey)
	if err != nil {
		panic(err)
	}
	if bz == nil {
		return 0
	}
	height := sdk.BigEndianToUint64(bz)
	return height
}

// ///////////////////////// mocking

//func (k Keeper) SetupAndProcessFinality(ctx sdk.Context, numFPs int) error {
//	height := uint64(ctx.BlockHeight())
//
//	// 1. Create a mock block
//	mockBlock := &types.IndexedBlock{
//		Height:    height,
//		AppHash:   bytes.Repeat([]byte{1}, 32), // 32 bytes mock AppHash
//		Finalized: false,
//	}
//	k.SetBlock(ctx, mockBlock)
//
//	//// 2. Mock BTCStaking activation height
//	//k.BTCStakingKeeper = &mockBTCStakingKeeper{
//	//	activatedHeight: 1,
//	//}
//
//	// Set GetBTCStakingActivatedHeight
//
//	//k.BTCStakingKeeper.GetBTCHeightAtBabylonHeight()
//
//	GenRandBtcChainInsertingInKeeper
//	-SetBaseBTCHeader
//	-insertHeader
//
//	btcTipHeight := k.BTCStakingKeeper.GetCurrentBTCHeight(ctx)
//
//	BeginBlocker
//	-UpdatePowerDist
//	-RecordVotingPowerAndCache
//
//	k.SetFinalityProvider
//
//	k.HandleResumeFinalityProposal()
//	-SetVotingPower
//	-AddFinalityProviderDistInfo
//	-SetVotingPowerDistCache
//	-HandleFPStateUpdates
//
//	// 3. Create and setup mock FPs with their voting power history
//	for i := 0; i < numFPs; i++ {
//		// Generate deterministic FP key for testing
//		fpPrivKey := make([]byte, 32)
//		binary.BigEndian.PutUint32(fpPrivKey, uint32(i))
//		fpPubKey, err := bbn.NewBIP340PubKey(fpPrivKey)
//		if err != nil {
//			return err
//		}
//
//		// Set current and historical voting power for the FP
//		fpPubKeyBytes := []byte(fpPubKey.MarshalHex())
//		k.SetVotingPower(ctx, fpPubKeyBytes, height, 1)
//
//		// Set historical voting power for liveness checking
//		for h := height - 100; h <= height; h++ {
//			k.SetHistoricalVotingPower(ctx, fpPubKeyBytes, h, 1)
//		}
//
//		// Create mock signature
//		mockSig, err := bbn.NewSchnorrEOTSSig(bytes.Repeat([]byte{byte(i)}, 32))
//		if err != nil {
//			return err
//		}
//
//		// Add finality signature
//		err = k.AddFinalitySig(ctx, height, fpPubKey, mockSig)
//		if err != nil {
//			return err
//		}
//	}
//
//	// 4. Mock other required dependencies
//	k.incentiveKeeper = &mockIncentiveKeeper{}
//	k.checkpointingKeeper = &mockCheckpointingKeeper{
//		lastFinalizedEpoch: height / 100, // Assuming epoch size is 100
//	}
//
//	// 5. Execute finality processing logic
//	k.TallyBlocks(ctx, 10000)
//
//	// 6. Handle liveness checks
//	k.HandleLiveness(ctx, height)
//
//	// 7. Handle rewarding
//	k.HandleRewarding(ctx, height, types.MaxFinalizedRewardedBlocksPerEndBlock)
//
//	return nil
//}
//
//// Enhanced mock implementations
//type mockBTCStakingKeeper struct {
//	activatedHeight uint64
//}
//
//func (m *mockBTCStakingKeeper) GetBTCStakingActivatedHeight(ctx sdk.Context) uint64 {
//	return m.activatedHeight
//}
//
//func (m *mockBTCStakingKeeper) GetFinalityProviderSet(ctx sdk.Context, height uint64) [][]byte {
//	// Return mock FP set
//	return [][]byte{} // Will be populated by actual FPs we create
//}
//
//type mockIncentiveKeeper struct{}
//
//func (m *mockIncentiveKeeper) RewardBTCStaking(ctx sdk.Context, epoch uint64, fpPks [][]byte, finalizedHeight uint64) {
//	// No-op for testing
//}
//
//func (m *mockIncentiveKeeper) SlashBTCStaking(ctx sdk.Context, fpPk []byte, slashFactor sdk.Dec) {
//	// No-op for testing
//}
//
//type mockCheckpointingKeeper struct {
//	lastFinalizedEpoch uint64
//}
//
//func (m *mockCheckpointingKeeper) GetLatestFinalizedEpoch(ctx sdk.Context) uint64 {
//	return m.lastFinalizedEpoch
//}
//
//// Helper function to set historical voting power
//func (k Keeper) SetHistoricalVotingPower(ctx sdk.Context, fpPubKey []byte, height uint64, power uint64) {
//	store := ctx.KVStore(k.storeKey)
//	key := types.GetVotingPowerKey(fpPubKey, height)
//	store.Set(key, sdk.Uint64ToBigEndian(power))
//}
