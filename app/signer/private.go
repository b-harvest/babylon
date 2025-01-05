package signer

import (
	"path/filepath"

	cmtconfig "github.com/cometbft/cometbft/config"
	cmtos "github.com/cometbft/cometbft/libs/os"

	"github.com/babylonlabs-io/babylon/privval"
	cometbftprivval "github.com/cometbft/cometbft/privval"
)

type PrivSigner struct {
	WrappedPV *privval.WrappedFilePV
}

func InitPrivSigner(nodeDir, password string) (*PrivSigner, error) {
	nodeCfg := cmtconfig.DefaultConfig()
	pvKeyFile := filepath.Join(nodeDir, nodeCfg.PrivValidatorKeyFile())
	err := cmtos.EnsureDir(filepath.Dir(pvKeyFile), 0777)
	if err != nil {
		return nil, err
	}
	pvStateFile := filepath.Join(nodeDir, nodeCfg.PrivValidatorStateFile())
	err = cmtos.EnsureDir(filepath.Dir(pvStateFile), 0777)
	if err != nil {
		return nil, err
	}

	// wonjoon: create FilePV from cometBFT
	// todo: is it always load pv from file?
	// if not exists, should generate new file but prev version only load from file
	cometPv := cometbftprivval.LoadOrGenFilePV(pvKeyFile, pvStateFile)

	// wonjoon: create BlsPV from bls pv file path
	// todo: check path is correct
	blsCfg := privval.DefaultBlsConfig()
	blsKeyFile := blsCfg.BlsKeyFile()
	err = cmtos.EnsureDir(filepath.Dir(blsKeyFile), 0777)
	if err != nil {
		return nil, err
	}
	// blsPv := privval.LoadBlsPV(blsKeyFile, password)
	// todo: get mnemonic from outside
	blsPv := privval.LoadOrGenBlsPV("", blsKeyFile, password)

	return &PrivSigner{
		WrappedPV: privval.NewWrappedFilePV(
			cometPv.Key,
			cometPv.LastSignState,
			blsPv.Key,
		),
	}, nil
}
