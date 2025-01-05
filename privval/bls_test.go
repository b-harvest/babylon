package privval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBLSPVKeyLifecycle(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "bls-test")
	require.NoError(t, err)
	// defer os.RemoveAll(tempDir)

	// Setup test parameters
	keyFilePath := filepath.Join(tempDir, "bls_key.json")
	t.Logf("BLS key file will be created at: %s", keyFilePath)
	password := "testpassword"

	// Test generating new BLS key
	newBlsPv := LoadOrGenBlsPV("", keyFilePath, password)
	require.NotNil(t, newBlsPv)
	require.FileExists(t, keyFilePath)

	// Test loading existing BLS key
	loadedBlsPv := LoadBlsPV(keyFilePath, password)
	require.NotNil(t, loadedBlsPv)

	// Compare original and loaded keys
	require.Equal(t, newBlsPv.Key.GetPrivKey(), loadedBlsPv.Key.GetPrivKey())
	require.Equal(t, newBlsPv.Key.GetPubKey().Bytes(), loadedBlsPv.Key.GetPubKey().Bytes())
}
