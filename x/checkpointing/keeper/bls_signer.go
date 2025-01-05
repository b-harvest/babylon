package keeper

import (
	"github.com/cometbft/cometbft/crypto"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	"github.com/babylonlabs-io/babylon/x/checkpointing/types"
)

type BlsSigner interface {
	GetAddress() sdk.ValAddress
	SignMsgWithBls(msg []byte) (bls12381.Signature, error)
	GetBlsPubkey() bls12381.PublicKey
	GetValidatorPubkey() crypto.PubKey
}

// SignBLS signs a BLS signature over the given information
func (k Keeper) SignBLS(epochNum uint64, blockHash types.BlockHash) (bls12381.Signature, error) {
	// get BLS signature by signing
	signBytes := types.GetSignBytes(epochNum, blockHash)
	return k.blsSigner.SignMsgWithBls(signBytes)
}

func (k Keeper) GetBLSSignerAddress() sdk.ValAddress {
	return k.blsSigner.GetAddress()
}

func (k Keeper) GetValidatorAddress() sdk.ValAddress {
	return sdk.ValAddress(k.blsSigner.GetValidatorPubkey().Address())
}
