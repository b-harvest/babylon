package signer

import (
	"fmt"

	cmtconfig "github.com/cometbft/cometbft/config"
	cmtprivval "github.com/cometbft/cometbft/privval"

	"github.com/babylonlabs-io/babylon/privval"
)

type PrivSigner struct {
	WrappedPV *privval.WrappedFilePV
}

// TODO: Removal is required, and refactoring is needed to ensure it is no longer called from the places that previously invoked it.
func InitPrivSigner(nodeDir string) (*PrivSigner, error) {
	//nodeCfg := cmtconfig.DefaultConfig()
	//nodeCfg.SetRoot(nodeDir)
	//
	//pvKeyFile := nodeCfg.PrivValidatorKeyFile()
	//pvStateFile := nodeCfg.PrivValidatorStateFile()
	//blsKeyFile := privval.DefaultBlsKeyFile(nodeDir)
	//blsPasswordFile := privval.DefaultBlsPasswordFile(nodeDir)
	//
	//if err := privval.EnsureDirs(pvKeyFile, pvStateFile, blsKeyFile, blsPasswordFile); err != nil {
	//	return nil, err
	//}
	//fmt.Println("InitPrivSigner")
	//cometPV := cmtprivval.LoadFilePV(pvKeyFile, pvStateFile)
	//blsPV := privval.LoadBlsPV(blsKeyFile, blsPasswordFile)
	//
	//wrappedPV := &privval.WrappedFilePV{
	//	Key: privval.WrappedFilePVKey{
	//		CometPVKey: cometPV.Key,
	//		BlsPVKey:   blsPV.Key,
	//	},
	//	LastSignState: cometPV.LastSignState,
	//}
	//
	//return &PrivSigner{
	//	WrappedPV: wrappedPV,
	//}, nil
	fmt.Println("InitPrivSigner")
	return nil, nil
}

// TODO: need to
func InitPrivSigner2(nodeDir string) (*PrivSigner, error) {
	nodeCfg := cmtconfig.DefaultConfig()
	nodeCfg.SetRoot(nodeDir)

	pvKeyFile := nodeCfg.PrivValidatorKeyFile()
	pvStateFile := nodeCfg.PrivValidatorStateFile()
	blsKeyFile := privval.DefaultBlsKeyFile(nodeDir)
	blsPasswordFile := privval.DefaultBlsPasswordFile(nodeDir)

	if err := privval.EnsureDirs(pvKeyFile, pvStateFile, blsKeyFile, blsPasswordFile); err != nil {
		return nil, fmt.Errorf("failed to ensure dirs: %w", err)
	}
	fmt.Println("InitPrivSigner2")
	cometPV := cmtprivval.LoadFilePV(pvKeyFile, pvStateFile)
	blsPV := privval.LoadBlsPV(blsKeyFile, blsPasswordFile)

	wrappedPV := &privval.WrappedFilePV{
		Key: privval.WrappedFilePVKey{
			CometPVKey: cometPV.Key,
			BlsPVKey:   blsPV.Key,
		},
		LastSignState: cometPV.LastSignState,
	}

	return &PrivSigner{
		WrappedPV: wrappedPV,
	}, nil
	//return nil, nil
}

func GetCometFilePV(nodeDir string) *cmtprivval.FilePV {
	nodeCfg := cmtconfig.DefaultConfig()
	nodeCfg.SetRoot(nodeDir)
	pvKeyFile := nodeCfg.PrivValidatorKeyFile()
	pvStateFile := nodeCfg.PrivValidatorStateFile()
	return cmtprivval.LoadFilePV(pvKeyFile, pvStateFile)
}
