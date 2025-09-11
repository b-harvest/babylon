package testnet

import (
	"context"
	"fmt"

	store "cosmossdk.io/store/types"
	upgradetypes "cosmossdk.io/x/upgrade/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/babylonlabs-io/babylon/v3/app/keepers"
	"github.com/babylonlabs-io/babylon/v3/app/upgrades"
	epochingkeeper "github.com/babylonlabs-io/babylon/v3/x/epoching/keeper"
	"github.com/babylonlabs-io/babylon/v3/x/epoching/types"
)

const UpgradeName = "v3rc4"

var Upgrade = upgrades.Upgrade{
	UpgradeName:          UpgradeName,
	CreateUpgradeHandler: CreateUpgradeHandler,
	StoreUpgrades: store.StoreUpgrades{
		Added:   []string{},
		Deleted: []string{},
	},
}

func CreateUpgradeHandler(mm *module.Manager, configurator module.Configurator, keepers *keepers.AppKeepers) upgradetypes.UpgradeHandler {
	return func(ctx context.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
		sdkCtx := sdk.UnwrapSDKContext(ctx)
		currentHeight := uint64(sdkCtx.HeaderInfo().Height)

		// Validate epoch boundary using the same logic as migration
		if err := validateEpochBoundaryFromStore(keepers, ctx, currentHeight); err != nil {
			return nil, fmt.Errorf("epoch boundary validation failed: %w", err)
		}

		// Validate delegation pool module account exists before running migrations
		if err := validateDelegatePoolModuleAccount(ctx, keepers.AccountKeeper); err != nil {
			return nil, fmt.Errorf("spam prevention upgrade validation failed: %w", err)
		}

		// Validate that current epoch has no queued messages
		if err := validateNoQueuedMessages(ctx, keepers.EpochingKeeper); err != nil {
			return nil, fmt.Errorf("queued messages validation failed: %w", err)
		}

		// Validate that delegation pool has no locked funds
		if err := validateDelegatePoolEmpty(ctx, keepers.AccountKeeper, keepers.BankKeeper); err != nil {
			return nil, fmt.Errorf("delegate pool validation failed: %w", err)
		}

		// Run migrations (includes epoching v1->v2 migration)
		migrations, err := mm.RunMigrations(ctx, configurator, fromVM)
		if err != nil {
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}

		if err := validateMigrationResults(ctx, keepers); err != nil {
			return nil, fmt.Errorf("migration validation failed: %w", err)
		}

		// Validate that no messages were added to queue during migration
		if err := validateNoQueuedMessages(ctx, keepers.EpochingKeeper); err != nil {
			return nil, fmt.Errorf("queued messages validation failed: %w", err)
		}

		// Log successful upgrade
		sdkCtx.Logger().Info("spam prevention upgrade completed successfully",
			"upgrade", UpgradeName,
			"epoching_migration", "v3rc3->v3rc4",
			"height", currentHeight,
			"epoch_boundary", true,
		)

		return migrations, nil
	}
}

// validateDelegatePoolModuleAccount validates that the delegation pool module account is properly configured
func validateDelegatePoolModuleAccount(ctx context.Context, ak types.AccountKeeper) error {
	// Use hardcoded module name to avoid dependency on upgraded types
	const delegatePoolModuleName = "epoching_delegate_pool"

	moduleAddr := ak.GetModuleAddress(delegatePoolModuleName)
	if moduleAddr == nil {
		return fmt.Errorf("module account %s has not been configured - ensure it's added to maccPerms in app.go",
			delegatePoolModuleName)
	}

	// Module account address exists, which means it's properly configured
	// The actual account object will be created when first used by the module
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	sdkCtx.Logger().Info("delegation pool module account validated",
		"module", delegatePoolModuleName,
		"address", moduleAddr.String())

	return nil
}

// validateDelegatePoolEmpty validates that the delegation pool module account has no locked funds
func validateDelegatePoolEmpty(ctx context.Context, ak types.AccountKeeper, bk interface{}) error {
	// Use hardcoded module name to avoid dependency on upgraded types
	const delegatePoolModuleName = "epoching_delegate_pool"

	moduleAddr := ak.GetModuleAddress(delegatePoolModuleName)
	if moduleAddr == nil {
		return fmt.Errorf("module account %s address not found", delegatePoolModuleName)
	}

	// Type assertion to access bank keeper methods
	bankKeeper, ok := bk.(interface {
		SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins
	})
	if !ok {
		return fmt.Errorf("invalid bank keeper type - cannot access balance methods")
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	balance := bankKeeper.SpendableCoins(ctx, moduleAddr)

	if !balance.IsZero() {
		return fmt.Errorf("upgrade cannot proceed with locked funds in delegation pool (balance: %s) - this indicates unprocessed queued messages with locked funds",
			balance.String())
	}

	sdkCtx.Logger().Info("delegation pool validation successful",
		"module", delegatePoolModuleName,
		"address", moduleAddr.String(),
		"balance", balance.String())

	return nil
}

// validateEpochBoundaryFromStore validates epoch boundary using migration logic
func validateEpochBoundaryFromStore(keepers *keepers.AppKeepers, ctx context.Context, currentHeight uint64) error {
	// Use the exact same logic as migration v2 store to read v1 params
	epochingStoreKey := keepers.GetKey(types.StoreKey)
	epochingStore := runtime.NewKVStoreService(epochingStoreKey)
	store := epochingStore.OpenKVStore(ctx)

	// Get the existing params bytes from store (same as migration)
	paramsBz, err := store.Get(types.ParamsKey)
	if err != nil {
		return fmt.Errorf("failed to get params from store: %w", err)
	}

	var epochInterval uint64
	if paramsBz == nil {
		// No existing params, use default (same as migration)
		epochInterval = 10 // DefaultEpochInterval from v1
	} else {
		// Unmarshal existing v1 params (same as migration logic)
		var params types.Params
		err := keepers.EncCfg.Codec.Unmarshal(paramsBz, &params)
		if err != nil {
			return fmt.Errorf("unmarshal existing v1 params: %w", err)
		}
		epochInterval = params.EpochInterval
	}

	// Now validate epoch boundary using the epochInterval
	return ValidateEpochBoundary(ctx, currentHeight, epochInterval)
}

// ValidateEpochBoundary performs the actual epoch boundary validation (exported for tests)
func ValidateEpochBoundary(ctx context.Context, currentHeight, epochInterval uint64) error {
	if currentHeight == 0 {
		// Genesis block is always epoch boundary
		return nil
	}

	// For height > 0, check if it's the first block of an epoch
	// First block of epoch N starts at height: (N-1) * epochInterval + 1
	// So height h is first block if: (h-1) % epochInterval == 0
	if epochInterval == 0 {
		return fmt.Errorf("epoch interval cannot be zero")
	}
	if (currentHeight-1)%epochInterval != 0 {
		currentEpoch := ((currentHeight - 1) / epochInterval) + 1
		nextEpochFirstBlock := (currentEpoch * epochInterval) + 1

		return fmt.Errorf("upgrade must happen at epoch boundary - current height %d is not first block of epoch %d (next epoch boundary at height %d)",
			currentHeight, currentEpoch, nextEpochFirstBlock)
	}

	return nil
}

// validateNoQueuedMessages ensures current epoch has no queued messages before upgrade
func validateNoQueuedMessages(ctx context.Context, epochingKeeper epochingkeeper.Keeper) error {
	// Direct access to keeper methods without type assertion
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	currentEpoch := epochingKeeper.GetEpoch(ctx)
	queueLength := epochingKeeper.GetCurrentQueueLength(ctx)

	if queueLength > 0 {
		return fmt.Errorf("upgrade cannot proceed with queued messages in current epoch %d (found %d queued messages) - please wait for epoch to end and messages to be processed",
			currentEpoch.EpochNumber, queueLength)
	}

	sdkCtx.Logger().Info("message queue validation successful",
		"current_epoch", currentEpoch.EpochNumber,
		"queue_length", queueLength)

	return nil
}

func validateMigrationResults(ctx context.Context, keepers *keepers.AppKeepers) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Validate epoching params after migration
	epochingParams := keepers.EpochingKeeper.GetParams(sdkCtx)
	if err := epochingParams.Validate(); err != nil {
		return fmt.Errorf("migrated epoching params validation failed: %w", err)
	}

	sdkCtx.Logger().Info("migration validation successful",
		"epoch_interval", epochingParams.EpochInterval,
		"min_amount", epochingParams.MinAmount,
		"delegate_gas", epochingParams.ExecuteGas.Delegate)

	return nil
}
