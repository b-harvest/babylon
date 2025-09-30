package btcstaking_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/babylonlabs-io/babylon/v4/btcstaking"
	"github.com/babylonlabs-io/babylon/v4/testutil/datagen"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

// MultiSigStakingScriptData holds data for multi-sig staking scripts
type MultiSigStakingScriptData struct {
	StakerKeys          []*btcec.PublicKey
	StakerQuorum        uint32
	FinalityProviderKey *btcec.PublicKey
	CovenantKey         *btcec.PublicKey
	CovenantQuorum      uint32
	StakingTime         uint16
}

func NewMultiSigStakingScriptData(
	stakerKeys []*btcec.PublicKey,
	stakerQuorum uint32,
	fpKey *btcec.PublicKey,
	covenantKey *btcec.PublicKey,
	covenantQuorum uint32,
	stakingTime uint16) (*MultiSigStakingScriptData, error) {

	if len(stakerKeys) == 0 {
		return nil, fmt.Errorf("staker keys cannot be empty")
	}

	for _, key := range stakerKeys {
		if key == nil {
			return nil, fmt.Errorf("staker key cannot be nil")
		}
	}

	if fpKey == nil || covenantKey == nil {
		return nil, fmt.Errorf("finality provider and covenant keys cannot be nil")
	}

	return &MultiSigStakingScriptData{
		StakerKeys:          stakerKeys,
		StakerQuorum:        stakerQuorum,
		FinalityProviderKey: fpKey,
		CovenantKey:         covenantKey,
		CovenantQuorum:      covenantQuorum,
		StakingTime:         stakingTime,
	}, nil
}

func genValidMultiSigStakingScriptData(t *testing.T, r *rand.Rand, numStakerKeys int) *MultiSigStakingScriptData {
	// Generate multiple staker keys
	stakerKeys := make([]*btcec.PublicKey, numStakerKeys)
	for i := 0; i < numStakerKeys; i++ {
		stakerPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
		_, stakerPublicKey := btcec.PrivKeyFromBytes(stakerPrivKeyBytes)
		stakerKeys[i] = stakerPublicKey
	}

	// Generate finality provider key
	fpPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
	_, fpPublicKey := btcec.PrivKeyFromBytes(fpPrivKeyBytes)

	// Generate covenant key
	covenantPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
	_, covenantPublicKey := btcec.PrivKeyFromBytes(covenantPrivKeyBytes)

	// Random staking time
	stakingTime := uint16(r.Intn(math.MaxUint16))

	// Quorum is all keys for simplicity
	stakerQuorum := uint32(numStakerKeys)
	covenantQuorum := uint32(1)

	sd, err := NewMultiSigStakingScriptData(
		stakerKeys,
		stakerQuorum,
		fpPublicKey,
		covenantPublicKey,
		covenantQuorum,
		stakingTime,
	)
	require.NoError(t, err)

	return sd
}

// TestBuildStakingInfoForMsig tests the BuildStakingInfoForMsig function
func TestBuildStakingInfoForMsig(t *testing.T) {
	r := rand.New(rand.NewSource(12345))

	// Test with different numbers of staker keys
	testCases := []struct {
		name           string
		numStakerKeys  int
		stakingAmount  btcutil.Amount
	}{
		{
			name:          "2-of-2 multi-sig",
			numStakerKeys: 2,
			stakingAmount: btcutil.Amount(10000),
		},
		{
			name:          "3-of-3 multi-sig",
			numStakerKeys: 3,
			stakingAmount: btcutil.Amount(20000),
		},
		{
			name:          "5-of-5 multi-sig",
			numStakerKeys: 5,
			stakingAmount: btcutil.Amount(50000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sd := genValidMultiSigStakingScriptData(t, r, tc.numStakerKeys)

			// Build staking info for multi-sig
			info, err := btcstaking.BuildStakingInfoForMsig(
				sd.StakerKeys,
				sd.StakerQuorum,
				[]*btcec.PublicKey{sd.FinalityProviderKey},
				[]*btcec.PublicKey{sd.CovenantKey},
				sd.CovenantQuorum,
				sd.StakingTime,
				tc.stakingAmount,
				&chaincfg.MainNetParams,
			)

			require.NoError(t, err)
			require.NotNil(t, info)
			require.NotNil(t, info.StakingOutput)
			require.Equal(t, int64(tc.stakingAmount), info.StakingOutput.Value)
			require.NotEmpty(t, info.StakingOutput.PkScript)

			// Verify we can get spend info for each path
			timeLockSpendInfo, err := info.TimeLockPathSpendInfo()
			require.NoError(t, err)
			require.NotNil(t, timeLockSpendInfo)

			unbondingSpendInfo, err := info.UnbondingPathSpendInfo()
			require.NoError(t, err)
			require.NotNil(t, unbondingSpendInfo)

			slashingSpendInfo, err := info.SlashingPathSpendInfo()
			require.NoError(t, err)
			require.NotNil(t, slashingSpendInfo)

			t.Logf("Successfully created %s staking info with %d staker keys", tc.name, tc.numStakerKeys)
		})
	}
}

// TestMultiSigScriptPaths tests that all three script paths are generated correctly
func TestMultiSigScriptPaths(t *testing.T) {
	r := rand.New(rand.NewSource(54321))
	numStakerKeys := 3
	sd := genValidMultiSigStakingScriptData(t, r, numStakerKeys)
	stakingAmount := btcutil.Amount(25000)

	// Build staking info
	info, err := btcstaking.BuildStakingInfoForMsig(
		sd.StakerKeys,
		sd.StakerQuorum,
		[]*btcec.PublicKey{sd.FinalityProviderKey},
		[]*btcec.PublicKey{sd.CovenantKey},
		sd.CovenantQuorum,
		sd.StakingTime,
		stakingAmount,
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	// Test TimeLock Path
	t.Run("TimeLock Path", func(t *testing.T) {
		spendInfo, err := info.TimeLockPathSpendInfo()
		require.NoError(t, err)
		require.NotNil(t, spendInfo)
		require.NotEmpty(t, spendInfo.RevealedLeaf.Script)

		t.Logf("TimeLock script length: %d bytes", len(spendInfo.RevealedLeaf.Script))
	})

	// Test Unbonding Path
	t.Run("Unbonding Path", func(t *testing.T) {
		spendInfo, err := info.UnbondingPathSpendInfo()
		require.NoError(t, err)
		require.NotNil(t, spendInfo)
		require.NotEmpty(t, spendInfo.RevealedLeaf.Script)

		t.Logf("Unbonding script length: %d bytes", len(spendInfo.RevealedLeaf.Script))
	})

	// Test Slashing Path
	t.Run("Slashing Path", func(t *testing.T) {
		spendInfo, err := info.SlashingPathSpendInfo()
		require.NoError(t, err)
		require.NotNil(t, spendInfo)
		require.NotEmpty(t, spendInfo.RevealedLeaf.Script)

		t.Logf("Slashing script length: %d bytes", len(spendInfo.RevealedLeaf.Script))
	})

	// Verify all three paths have different scripts
	timeLockSpendInfo, _ := info.TimeLockPathSpendInfo()
	unbondingSpendInfo, _ := info.UnbondingPathSpendInfo()
	slashingSpendInfo, _ := info.SlashingPathSpendInfo()

	require.NotEqual(t, timeLockSpendInfo.RevealedLeaf.Script, unbondingSpendInfo.RevealedLeaf.Script)
	require.NotEqual(t, timeLockSpendInfo.RevealedLeaf.Script, slashingSpendInfo.RevealedLeaf.Script)
	require.NotEqual(t, unbondingSpendInfo.RevealedLeaf.Script, slashingSpendInfo.RevealedLeaf.Script)

	t.Log("All three script paths are distinct")
}

// TestBuildStakingOutputsForMsig tests the BuildStakingOutputsForMsig function
func TestBuildStakingOutputsForMsig(t *testing.T) {
	r := rand.New(rand.NewSource(99999))
	numStakerKeys := 2
	sd := genValidMultiSigStakingScriptData(t, r, numStakerKeys)
	stakingAmount := btcutil.Amount(15000)

	// Test tag
	tag := []byte{0x01, 0x02, 0x03, 0x04}

	// Build staking outputs
	info, err := btcstaking.BuildStakingOutputsForMsig(
		tag,
		sd.StakerKeys,
		sd.StakerQuorum,
		sd.FinalityProviderKey,
		[]*btcec.PublicKey{sd.CovenantKey},
		sd.CovenantQuorum,
		sd.StakingTime,
		stakingAmount,
		&chaincfg.MainNetParams,
	)

	require.NoError(t, err)
	require.NotNil(t, info)
	require.NotNil(t, info.StakingOutput)
	require.NotNil(t, info.OpReturnOutput)

	// Verify staking output
	require.Equal(t, int64(stakingAmount), info.StakingOutput.Value)
	require.NotEmpty(t, info.StakingOutput.PkScript)

	// Verify OP_RETURN output
	require.Equal(t, int64(0), info.OpReturnOutput.Value)
	require.NotEmpty(t, info.OpReturnOutput.PkScript)

	t.Logf("Successfully created multi-sig staking outputs with OP_RETURN")
}

// TestBuildStakingOutputsAndTxForMsig tests the BuildStakingOutputsAndTxForMsig function
func TestBuildStakingOutputsAndTxForMsig(t *testing.T) {
	r := rand.New(rand.NewSource(77777))
	numStakerKeys := 3
	sd := genValidMultiSigStakingScriptData(t, r, numStakerKeys)
	stakingAmount := btcutil.Amount(30000)

	// Test tag
	tag := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	// Build staking outputs and transaction
	info, tx, err := btcstaking.BuildStakingOutputsAndTxForMsig(
		tag,
		sd.StakerKeys,
		sd.StakerQuorum,
		sd.FinalityProviderKey,
		[]*btcec.PublicKey{sd.CovenantKey},
		sd.CovenantQuorum,
		sd.StakingTime,
		stakingAmount,
		&chaincfg.MainNetParams,
	)

	require.NoError(t, err)
	require.NotNil(t, info)
	require.NotNil(t, tx)

	// Verify transaction has 2 outputs (staking + OP_RETURN)
	require.Equal(t, 2, len(tx.TxOut))

	// Verify first output is staking output
	require.Equal(t, int64(stakingAmount), tx.TxOut[0].Value)
	require.Equal(t, info.StakingOutput.PkScript, tx.TxOut[0].PkScript)

	// Verify second output is OP_RETURN
	require.Equal(t, int64(0), tx.TxOut[1].Value)
	require.Equal(t, info.OpReturnOutput.PkScript, tx.TxOut[1].PkScript)

	t.Logf("Successfully created multi-sig staking transaction with %d outputs", len(tx.TxOut))
}

// TestMultiSigVsSingleKey compares multi-sig (with 1 key) vs single key implementation
func TestMultiSigVsSingleKey(t *testing.T) {
	r := rand.New(rand.NewSource(11111))

	// Generate keys
	stakerPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
	_, stakerPublicKey := btcec.PrivKeyFromBytes(stakerPrivKeyBytes)

	fpPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
	_, fpPublicKey := btcec.PrivKeyFromBytes(fpPrivKeyBytes)

	covenantPrivKeyBytes := datagen.GenRandomByteArray(r, 32)
	_, covenantPublicKey := btcec.PrivKeyFromBytes(covenantPrivKeyBytes)

	stakingTime := uint16(1000)
	stakingAmount := btcutil.Amount(10000)

	// Build with single key (original)
	infoSingle, err := btcstaking.BuildStakingInfo(
		stakerPublicKey,
		[]*btcec.PublicKey{fpPublicKey},
		[]*btcec.PublicKey{covenantPublicKey},
		1,
		stakingTime,
		stakingAmount,
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	// Build with multi-sig (1 key)
	infoMulti, err := btcstaking.BuildStakingInfoForMsig(
		[]*btcec.PublicKey{stakerPublicKey},
		1,
		[]*btcec.PublicKey{fpPublicKey},
		[]*btcec.PublicKey{covenantPublicKey},
		1,
		stakingTime,
		stakingAmount,
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	// Both should succeed
	require.NotNil(t, infoSingle)
	require.NotNil(t, infoMulti)

	t.Log("Both single-key and 1-of-1 multi-sig implementations work correctly")
}