package checkpointing_test

import (
	"testing"

	"github.com/babylonlabs-io/babylon/privval"
	"github.com/babylonlabs-io/babylon/x/checkpointing"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	cosmosed "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	simapp "github.com/babylonlabs-io/babylon/app"
	"github.com/babylonlabs-io/babylon/x/checkpointing/types"
	cometbftprivval "github.com/cometbft/cometbft/privval"
)

func TestInitGenesis(t *testing.T) {
	app := simapp.Setup(t, false)
	ctx := app.BaseApp.NewContext(false)
	ckptKeeper := app.CheckpointingKeeper

	valNum := 10
	genKeys := make([]*types.GenesisKey, valNum)
	for i := 0; i < valNum; i++ {
		// wonjoon: modify to reflect changed function
		// valKeys, err := privval.NewValidatorKeys(ed25519.GenPrivKey(), bls12381.GenPrivKey())
		valKeys, err := func() (*privval.ValidatorKeys, error) {
			cometPv := cometbftprivval.NewFilePV(ed25519.GenPrivKey(), "", "")
			blsPv := privval.NewBlsPV("", "", "")
			return privval.NewValidatorKeys(cometPv.Key.PrivKey, blsPv.Key.GetPrivKey())
		}()
		require.NoError(t, err)
		valPubkey, err := cryptocodec.FromCmtPubKeyInterface(valKeys.ValPubkey)
		require.NoError(t, err)
		genKey, err := types.NewGenesisKey(
			sdk.ValAddress(valKeys.ValPubkey.Address()),
			&valKeys.BlsPubkey,
			valKeys.PoP,
			&cosmosed.PubKey{Key: valPubkey.Bytes()},
		)
		require.NoError(t, err)
		genKeys[i] = genKey
	}
	genesisState := types.GenesisState{
		GenesisKeys: genKeys,
	}

	checkpointing.InitGenesis(ctx, ckptKeeper, genesisState)
	for i := 0; i < valNum; i++ {
		addr, err := sdk.ValAddressFromBech32(genKeys[i].ValidatorAddress)
		require.NoError(t, err)
		blsKey, err := ckptKeeper.GetBlsPubKey(ctx, addr)
		require.NoError(t, err)
		require.True(t, genKeys[i].BlsKey.Pubkey.Equal(blsKey))
	}
}
