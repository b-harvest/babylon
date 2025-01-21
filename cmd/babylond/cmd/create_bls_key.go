package cmd

import (
	"strings"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"github.com/babylonlabs-io/babylon/app"
	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	"github.com/babylonlabs-io/babylon/privval"
)

func CreateBlsKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-bls-key",
		Short: "Create a pair of BLS keys for a validator",
		Long: strings.TrimSpace(`create-bls will create a pair of BLS keys that are used to
send BLS signatures for checkpointing.

BLS keys are stored along with other validator keys in priv_validator_key.json,
which should exist before running the command (via babylond init or babylond testnet).

Example:
$ babylond create-bls-key --home ./
`,
		),

		RunE: func(cmd *cobra.Command, args []string) error {
			homeDir, _ := cmd.Flags().GetString(flags.FlagHome)
			password, _ := cmd.Flags().GetString(flagBlsPassword)
			createBlsKey(bls12381.GenPrivKey(), homeDir, password)
			return nil
		},
	}

	cmd.Flags().String(flags.FlagHome, app.DefaultNodeHome, "The node home directory")
	cmd.Flags().String(flagBlsPassword, "", "The password for the BLS key. If a flag is set, the non-empty password should be provided. If a flag is not set, the password will be read from the prompt.")
	return cmd
}

func createBlsKey(privKey bls12381.PrivateKey, homeDir, password string) *privval.BlsPV {
	if password == "" {
		password = privval.NewBlsPassword()
	}
	pv := privval.NewBlsPV(privKey, privval.DefaultBlsKeyFile(homeDir), privval.DefaultBlsPasswordFile(homeDir))
	pv.Key.Save(password)
	return pv
}
