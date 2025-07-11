package btcstaking

import (
	"context"
	"time"

	"github.com/babylonlabs-io/babylon/v2/x/btcstaking/keeper"
	"github.com/babylonlabs-io/babylon/v2/x/btcstaking/types"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cosmos/cosmos-sdk/telemetry"
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"math/rand"
	bbntypes "github.com/babylonlabs-io/babylon/v2/types"
	btcctypes "github.com/babylonlabs-io/babylon/v2/x/btccheckpoint/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/babylonlabs-io/babylon/v2/testutil/datagen"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	sdkmath "cosmossdk.io/math"
	"github.com/babylonlabs-io/babylon/v2/btcstaking"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"golang.org/x/crypto/ripemd160"
	"io"
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func GenRandomByteArray(r *rand.Rand, length uint64) []byte {
	newHeaderBytes := make([]byte, length)
	r.Read(newHeaderBytes)
	return newHeaderBytes
}

func GenRandomHexStr(r *rand.Rand, length uint64) string {
	randBytes := GenRandomByteArray(r, length)
	return hex.EncodeToString(randBytes)
}

func GenRandomPkHash(r *rand.Rand) []byte {
	md := ripemd160.New()
	io.WriteString(md, GenRandomHexStr(r, 20)) //nolint:errcheck
	return md.Sum(nil)
}

func GenRandomPubKeyHashScript(r *rand.Rand, net *chaincfg.Params) ([]byte, error) {
	addr, err := btcutil.NewAddressPubKeyHash(GenRandomPkHash(r), net)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(addr)
}

func GenBTCStakingSlashingInfoWithOutPoint(
	r *rand.Rand,
	btcNet *chaincfg.Params,
	outPoint *wire.OutPoint,
	stakerSK *btcec.PrivateKey,
	fpPKs []*btcec.PublicKey,
	covenantPKs []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingTimeBlocks uint16,
	stakingValue int64,
	slashingPkScript []byte,
	slashingRate sdkmath.LegacyDec,
	slashingChangeLockTime uint16,
) *datagen.TestStakingSlashingInfo {
	stakingInfo, _ := btcstaking.BuildStakingInfo(
		stakerSK.PubKey(),
		fpPKs,
		covenantPKs,
		covenantQuorum,
		stakingTimeBlocks,
		btcutil.Amount(stakingValue),
		btcNet,
	)

	tx := wire.NewMsgTx(2)
	// add the given tx input
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)
	tx.AddTxOut(stakingInfo.StakingOutput)

	// 2 outputs for changes and staking output
	changeAddrScript, _ := GenRandomPubKeyHashScript(r, btcNet)

	tx.AddTxOut(wire.NewTxOut(10000, changeAddrScript)) // output for change

	slashingMsgTx, _ := btcstaking.BuildSlashingTxFromStakingTxStrict(
		tx,
		datagen.StakingOutIdx,
		slashingPkScript,
		stakerSK.PubKey(),
		slashingChangeLockTime,
		2000,
		slashingRate,
		btcNet)
	slashingTx, _ := types.NewBTCSlashingTxFromMsgTx(slashingMsgTx)

	return &datagen.TestStakingSlashingInfo{
		StakingTx:   tx,
		SlashingTx:  slashingTx,
		StakingInfo: stakingInfo,
	}
}

func randOutPoint(r *rand.Rand) wire.OutPoint {
	hash, _ := chainhash.NewHash(GenRandomByteArray(r, chainhash.HashSize))
	// TODO this will be deterministic without seed but for now it is not that
	// important
	idx := r.Uint32()

	return wire.OutPoint{
		Hash:  *hash,
		Index: idx,
	}
}

type spendableOut struct {
	prevOut wire.OutPoint
	amount  btcutil.Amount
}

func makeSpendableOutWithRandOutPoint(r *rand.Rand, amount btcutil.Amount) spendableOut {
	out := randOutPoint(r)

	return spendableOut{
		prevOut: out,
		amount:  amount,
	}
}

func GenBTCStakingSlashingInfo(
	r *rand.Rand,
	btcNet *chaincfg.Params,
	stakerSK *btcec.PrivateKey,
	fpPKs []*btcec.PublicKey,
	covenantPKs []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingTimeBlocks uint16,
	stakingValue int64,
	slashingPkScript []byte,
	slashingRate sdkmath.LegacyDec,
	slashingChangeLockTime uint16,
) *datagen.TestStakingSlashingInfo {
	// an arbitrary input
	spend := makeSpendableOutWithRandOutPoint(r, btcutil.Amount(stakingValue+datagen.UnbondingTxFee))
	outPoint := &spend.prevOut
	return GenBTCStakingSlashingInfoWithOutPoint(
		r,
		btcNet,
		outPoint,
		stakerSK,
		fpPKs,
		covenantPKs,
		covenantQuorum,
		stakingTimeBlocks,
		stakingValue,
		slashingPkScript,
		slashingRate,
		slashingChangeLockTime,
	)
}

func CreateMsgDelegationForParams(
	r *rand.Rand,
	p *types.Params,
) (*types.MsgCreateBTCDelegation, *btcec.PrivateKey) {
	// staker related date
	delSK, delPK, _ := datagen.GenRandomBTCKeyPair(r)
	stPk := bbntypes.NewBIP340PubKeyFromBTCPK(delPK)
	// TODO: non-deterministic
	//staker := sdk.MustAccAddressFromBech32(datagen.GenRandomAccount().Address)
	staker := sdk.MustAccAddressFromBech32(datagen.GenRandomAccountWithSeed(r).Address)
	fmt.Println("staker", staker)
	pop, _ := datagen.NewPoPBTC(staker, delSK)
	// finality provider related data
	_, fpPk, _ := datagen.GenRandomBTCKeyPair(r)
	fpPkBBn := bbntypes.NewBIP340PubKeyFromBTCPK(fpPk)
	// covenants
	covPKs, _ := bbntypes.NewBTCPKsFromBIP340PKs(p.CovenantPks)

	//(*types.MsgCreateBTCDelegation)(0x140006771e0)(staker_addr:"bbn186vc8mza93th8esqqgnnfaqjnhrg2cecndcv73" pop:<btc_sig:"\307\034>\307\374\202\247\203\025\025\327wy\244>\2471\274\302\3679\033\000\203\212\345\313\204\323+dLNy~\305\274\016\233\027\225\327\301o\001\243\355\360\021\037\030\267a\351-\315/\037d\234\230\017{\004" > btc_pk:"h\277\021w\210<m\223\001\rO\003U\210.\370\336\351\330\311\350\314o\204O\371\034\" \241\003\351" fp_btc_pk_list:"\224m\245r\323\341u\207\031\227o\320y\364\376\032o\177)E;\"_\260\016D\022\202\230\330\245\021" staking_time:6151 staking_value:2400214794 staking_tx:"\002\000\000\000\001\322q\021j\007=\t\2433\016\\\"\314\235\200\004\376\236\035\311;u\344\363r\000?^K\305&92f\2033\000\377\377\377\377\002\n_\020\217\000\000\000\000\"Q 5\341,M\272\352\331q\352\227k\017[\276s\327\366\360\200\30303c\377>\0145\025\344\202\264\021\020'\000\000\000\000\000\000\031v\251\024|\266\265$\317\020\255\336\013\030F\373B\266\177\3119\006\230\375\210\254\000\000\000\000" staking_tx_inclusion_proof:<key:<index:1 hash:"?\307\270\216\3251\272%E\314`\2462\202/\344\212\371\302\261\237\320\203wU\"\314\262|\252_&" > proof:"\366\326\252$aL\221\241\315\223\340#\316\03765w\223\027\321\301\363\333\343\030\014t\261\n\316\303m" > slashing_tx:"\001\000\000\000\001@\333\313\031Y\216\262P\223d\331\364\210H\312Q\217M?\212\034\221\0000<?\376\237\215|\256i\000\000\000\000\000\377\377\377\377\002&V2%\000\000\000\000\031v\251\024\277e\n\350:\234\245f\335\264\016z\013oW\241\252\021x\"\210\254\024\001\336i\000\000\000\000\"Q \352\014\355\247W\217\271wH\374\206\\G\263\367\343P\300\262\362\343\356\312E\300Ld\301\323\227l\024\000\000\000\000" delegator_slashing_sig:"Z\016\035}\306R9O_a\2361\034\316\nG\230\330K7\347|\304I\235&h\313\323X\022\327\224\253\232RJm\357f\251\267\235W\203\353fQu\336\267\325\276\362\276Ei2\007z<\256\034\227" unbonding_time:200 unbonding_tx:"\002\000\000\000\001@\333\313\031Y\216\262P\223d\331\364\210H\312Q\217M?\212\034\221\0000<?\376\237\215|\256i\000\000\000\000\000\377\377\377\377\001\"[\020\217\000\000\000\000\"Q \354C#CplD\034\032i\225\341\224yng\276\373p\002\270\362\007\314\303`\363\024X\216\2242\000\000\000\000" unbonding_value:2400213794 unbonding_slashing_tx:"\001\000\000\000\001i\274\342Wv\246\357\262\022\237\033\227\3030\227\2371\260\247C\341\n\237OkUN8\360\330\205\355\000\000\000\000\000\377\377\377\377\002\"U2%\000\000\000\000\031v\251\024\277e\n\350:\234\245f\335\264\016z\013oW\241\252\021x\"\210\2540\376\335i\000\000\000\000\"Q \352\014\355\247W\217\271wH\374\206\\G\263\367\343P\300\262\362\343\356\312E\300Ld\301\323\227l\024\000\000\000\000" delegator_unbonding_slashing_sig:"vE\207\253g\245\216cT\261\365\343d\205\235\020f\252B\016^\\-\234\217x\266->e\t\202\256\200u\314`\250.;\231B\025jZ\362{\242d<yL\2714\226b\201\010\004S\223d%]" )
	//&types.MsgCreateBTCDelegation{
	//	StakerAddr:"bbn1aej43dxwuqdkfx0ph8knz387prfd7k507e20sq",
	//	Pop:(*types.ProofOfPossessionBTC)(0x1400050c320),
	//	BtcPk:(*types.BIP340PubKey)(0x140005b05d0),
	//	FpBtcPkList:[]types.BIP340PubKey{
	//		types.BIP340PubKey{0xaf, 0x61, 0x13, 0xdc, 0x3d, 0x75, 0xed, 0x67, 0x2, 0x25, 0xfe, 0x79, 0x18, 0xbf, 0x84, 0x3e, 0x56, 0xcc, 0x39, 0x30, 0x87, 0x9a, 0xc5, 0x8a, 0xd6, 0xf, 0x46, 0xab, 0xb4, 0xbb, 0xda, 0xda}},
	//		StakingTime:0x1494,
	//		StakingValue:3009713285,
	//		StakingTx:[]uint8{0x2, 0x0, 0x0, 0x0, 0x1, 0xe8, 0xbb, 0x32, 0xa4, 0xb7, 0xad, 0xc9, 0x80, 0x89, 0x42, 0xba, 0x75, 0x9e, 0x35, 0xc9, 0x57, 0xce, 0x94, 0x9d, 0xc6, 0xd0, 0x86, 0xc8, 0x4c, 0x44, 0x79, 0x3e, 0x26, 0x1b, 0x7f, 0x8a, 0xbe, 0x17, 0x26, 0xb7, 0xc2, 0x0, 0xff, 0xff, 0xff, 0xff, 0x2, 0x85, 0x94, 0x64, 0xb3, 0x0, 0x0, 0x0, 0x0, 0x22, 0x51, 0x20, 0x1b, 0x49, 0x36, 0x97, 0xc2, 0x43, 0xa1, 0xdc, 0x68, 0x75, 0x66, 0x1d, 0xb7, 0xbf, 0xe5, 0x9b, 0x4e, 0xcd, 0x2e, 0x7a, 0x90, 0x68, 0xae, 0xd1, 0x27, 0x83, 0x75, 0xf8, 0xf4, 0x8, 0xa9, 0x88, 0x10, 0x27, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x19, 0x76, 0xa9, 0x14, 0x4b, 0x9a, 0xd, 0x49, 0x38, 0x77, 0xfa, 0x50, 0x72, 0x5a, 0x37, 0xa4, 0xc3, 0xeb, 0x3, 0x4a, 0x7b, 0x9e, 0xeb, 0x6d, 0x88, 0xac, 0x0, 0x0, 0x0, 0x0},
	//		StakingTxInclusionProof:(*types.InclusionProof)(0x140004be240),
	//		SlashingTx:(*types.BTCSlashingTx)(0x140005b0c48),
	//		DelegatorSlashingSig:(*types.BIP340Signature)(0x140005342e8), UnbondingTime:0xc8, UnbondingTx:[]uint8{0x2, 0x0, 0x0, 0x0, 0x1, 0xa7, 0x81, 0x2a, 0x38, 0x62, 0x9f, 0xb, 0x9e, 0xb0, 0xc5, 0x87, 0x90, 0x2f, 0x61, 0x88, 0xa7, 0xf1, 0x9f, 0x61, 0xd4, 0xd0, 0xc1, 0x65, 0xf9, 0x2d, 0x26, 0xd7, 0x6a, 0xf0, 0x70, 0x73, 0x7e, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0x1, 0x9d, 0x90, 0x64, 0xb3, 0x0, 0x0, 0x0, 0x0, 0x22, 0x51, 0x20, 0xaa, 0xfb, 0x57, 0x3, 0xc0, 0xb6, 0xa, 0xc7, 0xb0, 0x5c, 0x25, 0x38, 0xc3, 0x69, 0x82, 0x6c, 0xbc, 0x54, 0x7b, 0x53, 0x1c, 0x99, 0x59, 0xfe, 0xac, 0xbc, 0xb1, 0xa3, 0x7b, 0x19, 0x4d, 0x9c, 0x0, 0x0, 0x0, 0x0}, UnbondingValue:3009712285, UnbondingSlashingTx:(*types.BTCSlashingTx)(0x140005b01b0), DelegatorUnbondingSlashingSig:(*types.BIP340Signature)(0x140005b0210)}

	stakingTimeBlocks := uint16(p.MinStakingTimeBlocks)
	//stakingTimeBlocks := uint16(randRange(r, int(p.MinStakingTimeBlocks), int(p.MaxStakingTimeBlocks)))
	stakingValue := p.MinStakingValueSat
	//stakingValue := int64(randRange(r, int(p.MinStakingValueSat), int(p.MaxStakingValueSat)))

	// always chose minimum unbonding time possible
	unbondingTime := p.UnbondingTimeBlocks

	testStakingInfo := GenBTCStakingSlashingInfo(
		r,
		&chaincfg.MainNetParams,
		delSK,
		[]*btcec.PublicKey{fpPk},
		covPKs,
		p.CovenantQuorum,
		stakingTimeBlocks,
		stakingValue,
		p.SlashingPkScript,
		p.SlashingRate,
		uint16(unbondingTime),
	)

	slashingSpendInfo, _ := testStakingInfo.StakingInfo.SlashingPathSpendInfo()

	// generate proper delegator sig
	delegatorSig, _ := testStakingInfo.SlashingTx.Sign(
		testStakingInfo.StakingTx,
		0,
		slashingSpendInfo.GetPkScriptPath(),
		delSK,
	)
	//require.NoError(t, err)

	prevBlock, _ := datagen.GenRandomBtcdBlock(r, 0, nil)
	btcHeaderWithProof := datagen.CreateBlockWithTransaction(r, &prevBlock.Header, testStakingInfo.StakingTx)
	//btcHeader := btcHeaderWithProof.HeaderBytes
	serializedStakingTx, _ := bbntypes.SerializeBTCTx(testStakingInfo.StakingTx)
	//require.NoError(t, err)

	stakingTxHash := make([]byte, 32)
	r.Read(stakingTxHash)

	btcHeaderHash, _ := bbntypes.NewBTCHeaderHashBytesFromHex(string(stakingTxHash))
	txKey := &btcctypes.TransactionKey{
		Index: uint32(1),
		Hash:  &btcHeaderHash,
	}

	txInclusionProof := types.NewInclusionProof(
		txKey,
		btcHeaderWithProof.SpvProof.MerkleNodes,
	)

	//stkTxHash := testStakingInfo.StakingTx.TxHash()
	//stkOutputIdx := uint32(0)

	unbondingValue := stakingValue - p.UnbondingFeeSat

	//unbondingInfo := generateUnbondingInfo(
	//	r,
	//	t,
	//	delSK,
	//	fpPk,
	//	stkTxHash,
	//	stkOutputIdx,
	//	uint16(unbondingTime),
	//	unbondingValue,
	//	p,
	//)

	msgCreateBTCDel := &types.MsgCreateBTCDelegation{
		StakerAddr:              staker.String(),
		BtcPk:                   stPk,
		FpBtcPkList:             []bbntypes.BIP340PubKey{*fpPkBBn},
		Pop:                     pop,
		StakingTime:             uint32(stakingTimeBlocks),
		StakingValue:            stakingValue,
		StakingTx:               serializedStakingTx,
		StakingTxInclusionProof: txInclusionProof,
		SlashingTx:              testStakingInfo.SlashingTx,
		DelegatorSlashingSig:    delegatorSig,
		//UnbondingTx:                   unbondingInfo.serializedUnbondingTx,
		UnbondingTime:  unbondingTime,
		UnbondingValue: unbondingValue,
		//UnbondingSlashingTx:           unbondingInfo.unbondingSlashingTx,
		//DelegatorUnbondingSlashingSig: unbondingInfo.unbondingSlashinSig,
	}

	return msgCreateBTCDel, delSK
}

func BeginBlocker(ctx context.Context, k keeper.Keeper) error {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	// TODO: need to considering non-deterministic randomness
	babylonHeight := uint64(sdk.UnwrapSDKContext(ctx).HeaderInfo().Height)
	r := rand.New(rand.NewSource(int64(babylonHeight)))
	//r := rand.New(rand.NewSource(int64(111111)))
	params := k.GetParams(ctx)
	msg, _ := CreateMsgDelegationForParams(r, &params)

	des := stakingtypes.Description{Moniker: msg.StakerAddr}
	cfp := types.MsgCreateFinalityProvider{
		Addr:        msg.StakerAddr,
		Description: &des,
		Commission: types.CommissionRates{
			sdkmath.LegacyOneDec(),
			sdkmath.LegacyOneDec(),
			sdkmath.LegacyOneDec(),
		},
		BtcPk: msg.BtcPk,
		Pop:   msg.Pop,
	}

	fps, _ := k.GetAllFinalityProviders(ctx)
	fmt.Println("Mock fps begin", len(fps))
	if len(fps) < 100 {
		err := k.AddFinalityProvider(ctx, &cfp)
		if err != nil {
			fmt.Println("Mock: btcstaking.AddFinalityProvider", msg, err)
		}
	}

	//fmt.Println("Mock: btcstaking.BeginBlock", msg, delsk)
	fmt.Println("Mock: btcstaking.BeginBlock")
	res, err := k.CreateBTCDelegationMock(ctx, msg)
	if err != nil {
		fmt.Println(res, err)
	}
	return k.BeginBlocker(ctx)
}

func EndBlocker(ctx context.Context, k keeper.Keeper) ([]abci.ValidatorUpdate, error) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)

	k.HaltIfBtcReorgLargerThanConfirmationDepth(ctx)

	return []abci.ValidatorUpdate{}, nil
}
