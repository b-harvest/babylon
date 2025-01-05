package datagen

import (
	"fmt"
	"path/filepath"

	cfg "github.com/cometbft/cometbft/config"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtos "github.com/cometbft/cometbft/libs/os"
	"github.com/cometbft/cometbft/p2p"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"

	"github.com/babylonlabs-io/babylon/privval"
	cometbftprivval "github.com/cometbft/cometbft/privval"
)

// InitializeNodeValidatorFiles creates private validator and p2p configuration files.
// wonjoon: why it is needed? unnescessary function since we can configure mnemonic address to "" if no mnemonic is provided
func InitializeNodeValidatorFiles(cometCfg *cfg.Config, addr sdk.AccAddress) (string, *privval.ValidatorKeys, error) {
	// todo: modify mnemonic, password for bls
	return InitializeNodeValidatorFilesFromMnemonic(cometCfg, privval.BlsConfig{}, "", "", addr)
}

func InitializeNodeValidatorFilesFromMnemonic(cometCfg *cfg.Config, blsCfg privval.BlsConfig, mnemonic, password string, addr sdk.AccAddress) (nodeID string, valKeys *privval.ValidatorKeys, err error) {
	if len(mnemonic) > 0 && !bip39.IsMnemonicValid(mnemonic) {
		return "", nil, fmt.Errorf("invalid mnemonic")
	}

	// wonjoon: comet configuration
	nodeKey, err := p2p.LoadOrGenNodeKey(cometCfg.NodeKeyFile())
	if err != nil {
		return "", nil, err
	}

	nodeID = string(nodeKey.ID())

	pvKeyFile := cometCfg.PrivValidatorKeyFile()
	if err := cmtos.EnsureDir(filepath.Dir(pvKeyFile), 0777); err != nil {
		return "", nil, err
	}

	pvStateFile := cometCfg.PrivValidatorStateFile()
	if err := cmtos.EnsureDir(filepath.Dir(pvStateFile), 0777); err != nil {
		return "", nil, err
	}

	var cometPvPrivKey cmtcrypto.PrivKey
	if len(mnemonic) == 0 {
		cometPvPrivKey = cmted25519.GenPrivKey()
	} else {
		cometPvPrivKey = cmted25519.GenPrivKeyFromSecret([]byte(mnemonic))
	}
	cometPv := cometbftprivval.NewFilePV(cometPvPrivKey, pvKeyFile, pvStateFile)

	// wonjoon: bls configuration
	blsKeyFile := blsCfg.BlsKeyFile()
	// wonjoon: GenBlsPV -> NewBlsPv already checks if mnemonic is empty
	blsPv := privval.GenBlsPV(mnemonic, blsKeyFile, password)

	valKeys, err = privval.NewValidatorKeys(cometPv.Key.PrivKey, blsPv.Key.GetPrivKey())
	if err != nil {
		return "", nil, err
	}

	return nodeID, valKeys, nil
}
