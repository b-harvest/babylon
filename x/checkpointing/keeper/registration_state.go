package keeper

import (
	"context"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	"github.com/babylonlabs-io/babylon/x/checkpointing/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type RegistrationState struct {
	cdc codec.BinaryCodec
	// addrToBlsKeys maps validator addresses to BLS public keys
	addrToBlsKeys storetypes.KVStore
	// blsKeysToAddr maps BLS public keys to validator addresses
	blsKeysToAddr storetypes.KVStore
	// blsKeysToPubKey maps BLS public keys to validator public keys
	blsKeysToPubKey storetypes.KVStore
}

func (k Keeper) RegistrationState(ctx context.Context) RegistrationState {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	return RegistrationState{
		cdc:             k.cdc,
		addrToBlsKeys:   prefix.NewStore(storeAdapter, types.AddrToBlsKeyPrefix),
		blsKeysToAddr:   prefix.NewStore(storeAdapter, types.BlsKeyToAddrPrefix),
		blsKeysToPubKey: prefix.NewStore(storeAdapter, types.BlsKeyToPubKeyPrefix),
	}
}

// CreateRegistration inserts the BLS key into the addr -> key and key -> addr storage
func (rs RegistrationState) CreateRegistration(key bls12381.PublicKey, valAddr sdk.ValAddress, pubkey []byte) error {
	blsPubKey, err := rs.GetBlsPubKey(valAddr)

	// we should disallow a validator to register with different BLS public keys
	if err == nil && !blsPubKey.Equal(key) {
		return types.ErrBlsKeyAlreadyExist.Wrapf("the validator has registered a BLS public key")
	}

	// we should disallow the same BLS public key is registered by different validators
	bkToAddrKey := types.BlsKeyToAddrKey(key)
	rawAddr := rs.blsKeysToAddr.Get(bkToAddrKey)
	addr := new(sdk.ValAddress)
	err = addr.Unmarshal(rawAddr)
	if err != nil {
		return err
	}
	if rawAddr != nil && !addr.Equals(valAddr) {
		return types.ErrBlsKeyAlreadyExist.Wrapf("same BLS public key is registered by another validator")
	}

	// save concrete BLS public key object
	blsPkKey := types.AddrToBlsKeyKey(valAddr)
	rs.addrToBlsKeys.Set(blsPkKey, key)
	rs.blsKeysToAddr.Set(bkToAddrKey, valAddr.Bytes())
	rs.blsKeysToPubKey.Set(bkToAddrKey, pubkey)

	return nil
}

// GetBlsPubKey retrieves BLS public key by validator's address
func (rs RegistrationState) GetBlsPubKey(addr sdk.ValAddress) (bls12381.PublicKey, error) {
	pkKey := types.AddrToBlsKeyKey(addr)
	rawBytes := rs.addrToBlsKeys.Get(pkKey)
	if rawBytes == nil {
		return nil, types.ErrBlsKeyDoesNotExist.Wrapf("BLS public key does not exist with address %s", addr)
	}
	pk := new(bls12381.PublicKey)
	err := pk.Unmarshal(rawBytes)

	return *pk, err
}

// GetBlsPubKey retrieves BLS public key by validator's address
func (rs RegistrationState) GetValAddr(key bls12381.PublicKey) (sdk.ValAddress, error) {
	pkKey := types.BlsKeyToAddrKey(key)
	rawBytes := rs.blsKeysToAddr.Get(pkKey)
	if rawBytes == nil {
		return nil, types.ErrValAddrDoesNotExist.Wrapf("validator address does not exist with BLS public key %s", key)
	}
	addr := new(sdk.ValAddress)
	err := addr.Unmarshal(rawBytes)

	return *addr, err
}

// Exists checks whether a BLS key exists
func (rs RegistrationState) Exists(addr sdk.ValAddress) bool {
	pkKey := types.AddrToBlsKeyKey(addr)
	return rs.addrToBlsKeys.Has(pkKey)
}

// GetPubKey retrieves ED25519 public key by BLS public key
func (rs RegistrationState) GetPubKey(key bls12381.PublicKey) ([]byte, error) {
	pkKey := types.BlsKeyToAddrKey(key)
	rawBytes := rs.blsKeysToPubKey.Get(pkKey)
	if rawBytes == nil {
		return nil, types.ErrPubKeyDoesNotExist.Wrapf("ED25519 public key does not exist with BLS public key %s", key)
	}
	return rawBytes, nil
}
