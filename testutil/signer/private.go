package signer

import (
	"os"

	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	cosmosed "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"

	"github.com/babylonlabs-io/babylon/app/signer"
	"github.com/babylonlabs-io/babylon/privval"
	checkpointingtypes "github.com/babylonlabs-io/babylon/x/checkpointing/types"
)

// SetupTestPrivSigner sets up a PrivSigner for testing
// wonjoon: add password parameter
func SetupTestPrivSigner(password string) (*signer.PrivSigner, error) {
	// Create a temporary node directory
	nodeDir, err := os.MkdirTemp("", "tmp-signer")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(nodeDir)
	}()
	privSigner, _ := signer.InitPrivSigner(nodeDir, password)
	return privSigner, nil
}

func GenesisKeyFromPrivSigner(ps *signer.PrivSigner) (*checkpointingtypes.GenesisKey, error) {
	// wonjoon: refactoring
	valKeys, err := privval.NewValidatorKeys(
		ps.WrappedPV.Keys.CometPvKey.PrivKey,
		ps.WrappedPV.Keys.BlsPvKey.GetPrivKey(),
	)
	if err != nil {
		return nil, err
	}
	valPubkey, err := cryptocodec.FromCmtPubKeyInterface(valKeys.ValPubkey)
	if err != nil {
		return nil, err
	}
	return checkpointingtypes.NewGenesisKey(
		ps.WrappedPV.GetAddress(),
		&valKeys.BlsPubkey,
		valKeys.PoP,
		&cosmosed.PubKey{Key: valPubkey.Bytes()},
	)
}
