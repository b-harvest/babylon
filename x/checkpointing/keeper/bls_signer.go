package keeper

import (
	"context"
	"fmt"

	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	"github.com/babylonlabs-io/babylon/x/checkpointing/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BlsSigner is an interface for signing BLS messages
type BlsSigner interface {
	SignMsgWithBls(msg []byte) (bls12381.Signature, error)
	GetBlsPubkey() (bls12381.PublicKey, error)
}

// SignBLS signs a BLS signature over the given information
func (k Keeper) SignBLS(epochNum uint64, blockHash types.BlockHash) (bls12381.Signature, error) {
	// get BLS signature by signing
	signBytes := types.GetSignBytes(epochNum, blockHash)
	return k.blsSigner.SignMsgWithBls(signBytes)
}

// GetValidatorAddress returns the validator address of the signer
func (k Keeper) GetValidatorAddress(ctx context.Context) (sdk.ValAddress, error) {
	blsPubKey, err := k.blsSigner.GetBlsPubkey()
	if err != nil {
		return nil, fmt.Errorf("failed to get BLS public key: %w", err)
	}
	return k.GetValAddr(ctx, blsPubKey)
}
