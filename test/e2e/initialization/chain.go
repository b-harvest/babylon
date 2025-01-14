package initialization

import (
	"log"

	cmtos "github.com/cometbft/cometbft/libs/os"
)

const (
	keyringPassphrase = "testpassphrase"
	keyringAppName    = "testnet"
)

// internalChain contains the same info as chain, but with the validator structs instead using the internal validator
// representation, with more derived data
type internalChain struct {
	chainMeta ChainMeta
	nodes     []*internalNode
}

func new(id, dataDir string) *internalChain {
	chainMeta := ChainMeta{
		Id:      id,
		DataDir: dataDir,
	}
	return &internalChain{
		chainMeta: chainMeta,
	}
}

func (c *internalChain) export() *Chain {
	exportNodes := make([]*Node, 0, len(c.nodes))
	for _, v := range c.nodes {
		exportNodes = append(exportNodes, v.export())

		// ======= TESTING START =======
		log.Print("==> export()")
		log.Print("=> v.export().ConfigDir: ", v.export().ConfigDir)

		if cmtos.FileExists(v.export().ConsensusKey.BlsPVKey.GetKeyFilePath()) {
			log.Print("=> file exists: blsKeyFile: ", v.export().ConsensusKey.BlsPVKey.GetKeyFilePath())
		} else {
			log.Print("=> file does not exist: blsKeyFile: ", v.export().ConsensusKey.BlsPVKey.GetKeyFilePath())
		}

		if cmtos.FileExists(v.export().ConsensusKey.BlsPVKey.GetPasswordFilePath()) {
			log.Print("=> file exists: blsPasswordFile: ", v.export().ConsensusKey.BlsPVKey.GetPasswordFilePath())
		} else {
			log.Print("=> file does not exist: blsPasswordFile: ", v.export().ConsensusKey.BlsPVKey.GetPasswordFilePath())
		}
		// ======= TESTING END =======
	}

	return &Chain{
		ChainMeta: c.chainMeta,
		Nodes:     exportNodes,
	}
}
