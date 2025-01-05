package privval

import (
	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	checkpointingtypes "github.com/babylonlabs-io/babylon/x/checkpointing/types"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type WrappedFilePV struct {
	Keys          WrappedFilePVKey
	LastSignState privval.FilePVLastSignState
}

type WrappedFilePVKey struct {
	CometPvKey privval.FilePVKey
	BlsPvKey   BlsPvKey
}

// NewWrapperFilePV
func NewWrappedFilePV(
	cometPvKey privval.FilePVKey,
	cometPvLastSignState privval.FilePVLastSignState,
	blsPvKey BlsPvKey,
) *WrappedFilePV {
	return &WrappedFilePV{
		Keys: WrappedFilePVKey{
			CometPvKey: cometPvKey,
			BlsPvKey:   blsPvKey,
		},
		LastSignState: cometPvLastSignState,
	}
}

// wonjoon: should be removed after refactoring
func GenWrappedFilePV(keyFilePath, stateFilePath string) *WrappedFilePV {
	return nil
}

// wonjoon: should be removed after refactoring
func LoadWrappedFilePV(keyFilePath, stateFilePath string) *WrappedFilePV {
	return nil
}

// wonjoon: should be removed after refactoring
func (pv *WrappedFilePV) ExportGenBls(filePath string) (outputFileName string, err error) {
	return "", nil
}

// wonjoon: Since we plan to create privval.FilePV and BlsPV objects externally
// and then inject them, we remove the LoadOrGenFilePV function for WrappedFilePV.
// func LoadOrGenWrappedFilePV(...) *WrappedFilePV {}

// Implements for BlsSigner interface
// x/checkpointing/keeper/bls_signer.go
// - GetAddress() sdk.ValAddress
// - SignMsgWithBls(msg []byte) (bls12381.Signature, error)
// - GetBlsPubkey() (bls12381.PublicKey, error)
// - GetValidatorPubkey() (crypto.PubKey, error)

// wonjoon: function for get delegatorAddress
func (pv *WrappedFilePV) GetAddress() types.ValAddress {
	// Get the validator's public key from CometPVKey
	pubKey := pv.Keys.CometPvKey.PubKey
	if pubKey == nil {
		return sdk.ValAddress{}
	}
	return sdk.ValAddress(pubKey.Address())
}

func (pv *WrappedFilePV) SignMsgWithBls(msg []byte) (bls12381.Signature, error) {
	privKey := pv.Keys.BlsPvKey.GetPrivKey()
	if privKey == nil {
		return nil, checkpointingtypes.ErrBlsPrivKeyDoesNotExist
	}
	return bls12381.Sign(privKey, msg), nil
}

func (pv *WrappedFilePV) GetBlsPubkey() bls12381.PublicKey {
	return pv.Keys.BlsPvKey.GetPubKey()
}

// wonjoon: validator public key is same as comet public key
// should be removed after refactoring
func (pv *WrappedFilePV) GetValidatorPubkey() crypto.PubKey {
	return pv.Keys.CometPvKey.PubKey
}

func (pv *WrappedFilePV) GetValPrivKey() crypto.PrivKey {
	return pv.Keys.CometPvKey.PrivKey
}
