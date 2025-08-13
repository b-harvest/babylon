package cmd

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/babylonlabs-io/babylon/v3/app/ante"
	"github.com/babylonlabs-io/babylon/v3/app/signer"
	cmtcfg "github.com/cometbft/cometbft/config"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	serverconfig "github.com/cosmos/cosmos-sdk/server/config"

	appparams "github.com/babylonlabs-io/babylon/v3/app/params"
	bbn "github.com/babylonlabs-io/babylon/v3/types"
)

type BtcConfig struct {
	Network string `mapstructure:"network"`
}

func defaultBabylonBtcConfig() BtcConfig {
	return BtcConfig{
		Network: string(bbn.BtcMainnet),
	}
}

type BlsConfig struct {
	BlsKeyFile string `mapstructure:"bls-key-file"`
}

func defaultBabylonBlsConfig() BlsConfig {
	return BlsConfig{
		BlsKeyFile: filepath.Join(cmtcfg.DefaultConfigDir, signer.DefaultBlsKeyName),
	}
}

type BabylonMempoolConfig struct {
	MaxGasWantedPerTx string `mapstructure:"max-gas-wanted-per-tx"`
}

func defaultBabylonMempoolConfig() BabylonMempoolConfig {
	return BabylonMempoolConfig{
		MaxGasWantedPerTx: strconv.Itoa(ante.DefaultMaxGasWantedPerTx),
	}
}

// bench 섹션
type FinalityBenchConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	FpCount uint32 `mapstructure:"fp_count"`
	VpPerFp uint64 `mapstructure:"vp_per_fp"`
}

// finality 루트 섹션
type FinalityConfig struct {
	Bench FinalityBenchConfig `mapstructure:"bench"`
}

type BabylonAppConfig struct {
	serverconfig.Config `mapstructure:",squash"`

	Wasm wasmtypes.NodeConfig `mapstructure:"wasm"`

	BtcConfig BtcConfig `mapstructure:"btc-config"`

	BlsConfig BlsConfig `mapstructure:"bls-config"`

	BabylonMempoolConfig BabylonMempoolConfig `mapstructure:"babylon-mempool"`

	Finality FinalityConfig `mapstructure:"finality"`
}

func DefaultBabylonAppConfig() *BabylonAppConfig {
	baseConfig := *serverconfig.DefaultConfig()
	// Update the default Mempool.MaxTxs to be 0 to make sure the PriorityNonceMempool is used
	baseConfig.Mempool.MaxTxs = 0
	// The SDK's default minimum gas price is set to "0.002ubbn" (empty value) inside
	// app.toml, in order to avoid spamming attacks due to transactions with 0 gas price.
	baseConfig.MinGasPrices = fmt.Sprintf("%f%s", appparams.GlobalMinGasPrice, appparams.BaseCoinUnit)
	return &BabylonAppConfig{
		Config:               baseConfig,
		Wasm:                 wasmtypes.DefaultNodeConfig(),
		BtcConfig:            defaultBabylonBtcConfig(),
		BlsConfig:            defaultBabylonBlsConfig(),
		BabylonMempoolConfig: defaultBabylonMempoolConfig(),
		Finality: FinalityConfig{
			Bench: FinalityBenchConfig{
				Enabled: true,
				FpCount: 3,
				VpPerFp: 100,
			},
		},
	}
}

func DefaultBabylonTemplate() string {
	return serverconfig.DefaultConfigTemplate + wasmtypes.DefaultConfigTemplate() + `
###############################################################################
###                        BLS configuration                                ###
###############################################################################

[bls-config]
# Path to the BLS key file (if empty, defaults to $HOME/.babylond/config/bls_key.json)
bls-key-file = "{{ .BlsConfig.BlsKeyFile }}"

###############################################################################
###                      Babylon Bitcoin configuration                      ###
###############################################################################

[btc-config]

# Configures which bitcoin network should be used for checkpointing
# valid values are: [mainnet, testnet, simnet, signet, regtest]
network = "{{ .BtcConfig.Network }}"

###############################################################################
###                      Babylon Mempool Configuration                      ###
###############################################################################

[babylon-mempool]
# This is the max allowed gas for any tx.
# This is only for local mempool purposes, and thus	is only ran on check tx.
max-gas-wanted-per-tx = "{{ .BabylonMempoolConfig.MaxGasWantedPerTx }}"


###############################################################################
###                         Finality Bench Config                           ###
###############################################################################
[finality.bench]
enabled   = {{ .Finality.Bench.Enabled }}
fp_count  = {{ .Finality.Bench.FpCount }}
vp_per_fp = {{ .Finality.Bench.VpPerFp }}
`
}
