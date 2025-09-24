package main

import (
	"os"
	"runtime/pprof"
	"runtime/trace"

	"cosmossdk.io/log"

	"github.com/babylonlabs-io/babylon/v2/app"
	"github.com/babylonlabs-io/babylon/v2/cmd/babylond/cmd"
	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"

	"github.com/babylonlabs-io/babylon/v2/app/params"
)

func main() {
	f, _ := os.Create("cpu.prof")
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	// Start execution tracing
	ftrace, _ := os.Create("trace.out")
	trace.Start(ftrace)
	defer trace.Stop()
	params.SetAddressPrefixes()
	rootCmd := cmd.NewRootCmd()

	if err := svrcmd.Execute(rootCmd, app.BabylonAppEnvPrefix, app.DefaultNodeHome); err != nil {
		log.NewLogger(rootCmd.OutOrStderr()).Error("failure when running app", "err", err)
		os.Exit(1)
	}
}
