package signer

import (
	"path/filepath"
	"testing"

	"github.com/babylonlabs-io/babylon/crypto/erc2335"
	"github.com/babylonlabs-io/babylon/privval"
	cmtconfig "github.com/cometbft/cometbft/config"
	cmtprivval "github.com/cometbft/cometbft/privval"
	"github.com/test-go/testify/assert"
)

func TestGeneratePrivSigner(t *testing.T) {
	nodeDir := t.TempDir()

	nodeCfg := cmtconfig.DefaultConfig()
	blsCfg := privval.DefaultBlsConfig()

	pvKeyFile := filepath.Join(nodeDir, nodeCfg.PrivValidatorKeyFile())
	pvStateFile := filepath.Join(nodeDir, nodeCfg.PrivValidatorStateFile())
	blsKeyFile := filepath.Join(nodeDir, blsCfg.BlsKeyFile())
	blsPasswordFile := filepath.Join(nodeDir, blsCfg.BlsPasswordFile())

	err := privval.IsValidFilePath(pvKeyFile, pvStateFile, blsKeyFile, blsPasswordFile)
	assert.NoError(t, err)

	cometPV := cmtprivval.GenFilePV(pvKeyFile, pvStateFile)
	cometPV.Key.Save()
	cometPV.LastSignState.Save()

	privval.GenBlsPV(blsKeyFile, blsPasswordFile, "password", "")

	password, err := erc2335.LoadPaswordFromFile(blsPasswordFile)
	assert.NoError(t, err)
	t.Logf("password: %s", password)
}
