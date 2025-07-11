package keeper

import (
	"context"
	"fmt"

	"cosmossdk.io/collections"
	corestoretypes "cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/babylonlabs-io/babylon/v2/x/finality/types"
	"github.com/babylonlabs-io/babylon/v2/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/v2/types"
	"math/rand"
)

type (
	Keeper struct {
		cdc          codec.BinaryCodec
		storeService corestoretypes.KVStoreService

		BTCStakingKeeper    types.BTCStakingKeeper
		IncentiveKeeper     types.IncentiveKeeper
		CheckpointingKeeper types.CheckpointingKeeper
		// the address capable of executing a MsgUpdateParams message. Typically, this
		// should be the x/gov module account.
		authority string

		// FinalityProviderSigningTracker key: BIP340PubKey bytes | value: FinalityProviderSigningInfo
		FinalityProviderSigningTracker collections.Map[[]byte, types.FinalityProviderSigningInfo]
		// FinalityProviderMissedBlockBitmap key: BIP340PubKey bytes | value: byte key for a finality provider's missed block bitmap chunk
		FinalityProviderMissedBlockBitmap collections.Map[collections.Pair[[]byte, uint64], []byte]
	}
)

func NewKeeper(
	cdc codec.BinaryCodec,
	storeService corestoretypes.KVStoreService,
	btcstakingKeeper types.BTCStakingKeeper,
	incentiveKeeper types.IncentiveKeeper,
	checkpointingKeeper types.CheckpointingKeeper,
	authority string,
) Keeper {
	sb := collections.NewSchemaBuilder(storeService)
	return Keeper{
		cdc:          cdc,
		storeService: storeService,

		BTCStakingKeeper:    btcstakingKeeper,
		IncentiveKeeper:     incentiveKeeper,
		CheckpointingKeeper: checkpointingKeeper,
		authority:           authority,
		FinalityProviderSigningTracker: collections.NewMap(
			sb,
			types.FinalityProviderSigningInfoKeyPrefix,
			"finality_provider_signing_info",
			collections.BytesKey,
			codec.CollValue[types.FinalityProviderSigningInfo](cdc),
		),
		FinalityProviderMissedBlockBitmap: collections.NewMap(
			sb,
			types.FinalityProviderMissedBlockBitmapKeyPrefix,
			"finality_provider_missed_block_bitmap",
			collections.PairKeyCodec(collections.BytesKey, collections.Uint64Key),
			collections.BytesValue,
		),
	}
}

func AddFinalitySigMockFuzz(ctx context.Context, k Keeper) {
	// TODO: i, iterating
	cnt := 0
	for i := 0; i < 100; i++ {
		r := rand.New(rand.NewSource(int64(i)))
		//bsKeeper := types.NewMockBTCStakingKeeper(ctrl)
		//bsKeeper.EXPECT().UpdateFinalityProvider(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		//cKeeper := types.NewMockCheckpointingKeeper(ctrl)
		//iKeeper := types.NewMockIncentiveKeeper(ctrl)
		//iKeeper.EXPECT().IndexRefundableMsg(gomock.Any(), gomock.Any()).AnyTimes()
		//fKeeper, ctx := keepertest.FinalityKeeper(t, bsKeeper, iKeeper, cKeeper)
		//ms := keeper.NewMsgServerImpl(*fKeeper)

		// create and register a random finality provider
		btcSK, btcPK, _ := datagen.GenRandomBTCKeyPair(r)
		//fp, _ := datagen.GenRandomFinalityProviderWithBTCSK(r, btcSK)
		fpBTCPK := bbn.NewBIP340PubKeyFromBTCPK(btcPK)
		//fpBTCPKBytes := fpBTCPK.MustMarshal()

		// set committed epoch num
		//committedEpochNum := datagen.GenRandomEpochNum(r) + 1

		// commit some public randomness
		startHeight := uint64(0)
		numPubRand := uint64(200)
		//randListInfo, msgCommitPubRandList, err := datagen.GenRandomMsgCommitPubRandList(r, btcSK, startHeight, numPubRand)
		randListInfo, _, _ := datagen.GenRandomMsgCommitPubRandList(r, btcSK, startHeight, numPubRand)
		//_, err = ms.CommitPubRandList(ctx, msgCommitPubRandList)

		// generate a vote
		blockHeight := startHeight + uint64(1)
		blockAppHash := datagen.GenRandomByteArray(r, 32)
		// TODO: non-dterminism
		signer := datagen.GenRandomAccountWithSeed(r).Address
		//fmt.Println(signer)
		msg, _ := datagen.NewMsgAddFinalitySig(signer, btcSK, startHeight, blockHeight, randListInfo, blockAppHash)
		//ctx = ctx.WithHeaderInfo(header.Info{Height: int64(blockHeight)})
		//fKeeper.IndexBlock(ctx)

		//// Case 0: fail if the committed epoch is not finalized
		//lastFinalizedEpoch := datagen.RandomInt(r, int(committedEpochNum))
		//fKeeper.SetVotingPower(ctx, fpBTCPKBytes, blockHeight, 1)
		//_, err = ms.AddFinalitySig(ctx, msg)
		//
		//// set the committed epoch finalized for the rest of the cases
		//lastFinalizedEpoch = datagen.GenRandomEpochNum(r) + committedEpochNum
		//
		//// Case 1: fail if the finality provider does not have voting power
		//fKeeper.SetVotingPower(ctx, fpBTCPKBytes, blockHeight, 0)
		//_, err = ms.AddFinalitySig(ctx, msg)
		//
		//// mock voting power
		//fKeeper.SetVotingPower(ctx, fpBTCPKBytes, blockHeight, 1)

		// Case 3: successful if the finality provider has voting power and has not casted this vote yet
		// index this block first
		//ctx = ctx.WithHeaderInfo(header.Info{Height: int64(blockHeight), AppHash: blockAppHash})
		k.IndexBlock(ctx)
		// add vote and it should work
		_, err := k.AddFinalitySigMock(ctx, msg)
		// query this vote and assert
		k.GetSig(ctx, blockHeight, fpBTCPK)
		if err == nil {
			cnt += 1
		}
	}
	fmt.Println("AddFinalitySigMock", cnt)
}

func (k Keeper) BeginBlocker(ctx context.Context) error {
	// update voting power distribution
	k.UpdatePowerDist(ctx)

	// Add FinSig for tally
	AddFinalitySigMockFuzz(ctx, k)

	return nil
}

func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

func (k Keeper) GetLastFinalizedEpoch(ctx context.Context) uint64 {
	return k.CheckpointingKeeper.GetLastFinalizedEpoch(ctx)
}

func (k Keeper) GetCurrentEpoch(ctx context.Context) uint64 {
	currentEpoch := k.CheckpointingKeeper.GetEpoch(ctx)
	if currentEpoch == nil {
		panic("cannot get the current epoch")
	}

	return currentEpoch.EpochNumber
}

// IsFinalityActive returns true if the finality is activated and ready
// to start handling liveness, tally and index blocks.
func (k Keeper) IsFinalityActive(ctx context.Context) (activated bool) {
	if uint64(sdk.UnwrapSDKContext(ctx).HeaderInfo().Height) < k.GetParams(ctx).FinalityActivationHeight {
		return false
	}

	_, err := k.GetBTCStakingActivatedHeight(ctx)
	return err == nil
}
