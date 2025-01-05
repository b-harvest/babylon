package privval

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/babylonlabs-io/babylon/crypto/bls12381"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtos "github.com/cometbft/cometbft/libs/os"

	cometcfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/tempfile"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

const DefaultBlsKeyName = "bls_key.json"

var defaultBlsKeyFilePath = filepath.Join(cometcfg.DefaultDataDir, DefaultBlsKeyName)

type BlsPV struct {
	Key BlsPvKey
}

type BlsPvKey struct {
	pubKey   bls12381.PublicKey
	privKey  bls12381.PrivateKey
	filePath string
	password string
}

// wonjoon: If it were as intended, I would want to inject the BlsConfig object,
// but to match the FilePV format of cometbft, I would inject each item as a parameter.
// todo: mnemonic handling
func NewBlsPV(mnemonic, filePath, password string) *BlsPV {
	var privKey bls12381.PrivateKey

	if len(mnemonic) == 0 {
		privKey = bls12381.GenPrivKey()
	} else {
		privKey = bls12381.GenPrivKeyFromSecret([]byte(mnemonic))
	}
	return &BlsPV{
		Key: BlsPvKey{
			pubKey:   privKey.PubKey(),
			privKey:  privKey,
			filePath: filePath,
			password: password,
		},
	}
}

func (k *BlsPvKey) GetPubKey() bls12381.PublicKey {
	return k.pubKey
}

func (k *BlsPvKey) GetPrivKey() bls12381.PrivateKey {
	return k.privKey
}

// copied from github.com/cometbft/cometbft/privval/file.go
func (pv *BlsPV) Save() {
	pv.Key.Save()
}

// copied from github.com/cometbft/cometbft/privval/file.go
func (k *BlsPvKey) Save() {
	outFile := k.filePath
	if outFile == "" {
		panic("cannot save PrivValidator BLS key: filePath not set")
	}

	erc2335BlsPvKey, err := k.GenErc2335BlsPvKey()
	if err != nil {
		panic(err)
	}

	jsonBytes, err := cmtjson.MarshalIndent(erc2335BlsPvKey, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0600); err != nil {
		panic(err)
	}
}

func LoadOrGenBlsPV(mnemonic, keyFilePath, password string) *BlsPV {
	var pv *BlsPV
	if cmtos.FileExists(keyFilePath) {
		pv = LoadBlsPV(keyFilePath, password)
	} else {
		pv = GenBlsPV(mnemonic, keyFilePath, password)
		pv.Save()
	}
	return pv
}

func GenBlsPV(mnemonic, keyFilePath, password string) *BlsPV {
	return NewBlsPV(mnemonic, keyFilePath, password)
}

func LoadBlsPV(keyFilePath, password string) *BlsPV {
	return loadBlsPv(keyFilePath, password)
}

func loadBlsPv(keyFilePath, password string) *BlsPV {
	keyJSONBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		cmtos.Exit(err.Error())
	}
	erc2335BlsPvKey := Erc2335BlsPvKey{}
	err = cmtjson.Unmarshal(keyJSONBytes, &erc2335BlsPvKey)
	if err != nil {
		cmtos.Exit(fmt.Sprintf("Error reading PrivValidator BLS key from %v: %v\n", keyFilePath, err))
	}

	// k, err := erc2335BlsPvKey.DecryptErc2335BlsPvKey(keyFilePath, password)
	// if err != nil {
	// 	cmtos.Exit(fmt.Sprintf("Error converting erc2355 BLS key: %v\n", err))
	// }
	blsPrivKey, err := erc2335BlsPvKey.DecryptErc2335BlsPvKey(password)
	if err != nil {
		cmtos.Exit(fmt.Sprintf("Error converting erc2355 BLS key: %v\n", err))
	}

	return &BlsPV{
		Key: BlsPvKey{
			pubKey:   blsPrivKey.PubKey(),
			privKey:  blsPrivKey,
			filePath: keyFilePath,
			password: password,
		},
	}
}

// -------------------------------------------------------------------------------
// ---------------------------- BLS Config ---------------------------------------
// -------------------------------------------------------------------------------

type BlsConfig struct {
	RootDir    string `mapstructure:"home"`
	BlsKeyPath string `mapstructure:"bls_key_file"`
	Password   string `mapstructure:"password"`
}

func DefaultBlsConfig() BlsConfig {
	return BlsConfig{
		RootDir:    cometcfg.DefaultDataDir,
		BlsKeyPath: defaultBlsKeyFilePath,
		Password:   "",
	}
}

func (cfg BlsConfig) BlsKeyFile() string {
	return rootify(cfg.BlsKeyPath, cfg.RootDir)
}

// copied from github.com/cometbft/cometbft/config/config.go
func rootify(path, root string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

// -------------------------------------------------------------------------------
// ---------------------------- ERC 2335 -----------------------------------------
// -------------------------------------------------------------------------------

// ERC2335BLSPVKey is a BLS key with ERC2335 structure.
type Erc2335BlsPvKey struct {
	Crypto struct {
		KDF struct {
			Function string `json:"function"` // "pbkdf2"
			Params   struct {
				Dklen int    `json:"dklen"` // 32
				C     int    `json:"c"`     // 262144
				Prf   string `json:"prf"`   // "hmac-sha256"
				Salt  string `json:"salt"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string                 `json:"function"` // "sha256"
			Params   map[string]interface{} `json:"params"`
			Message  string                 `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"` // "aes-128-ctr"
			Params   struct {
				IV string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Description string `json:"description"` // "BLS-12381 private key"
	Pubkey      string `json:"pubkey"`      // hex-encoded public key
	Path        string `json:"path"`        // "m/12381/60/0/0"
	UUID        string `json:"uuid"`        // random UUID
	Version     int    `json:"version"`     // 4
}

// Generate ERC2335 standard BLS key from BlsPvKey
func (k *BlsPvKey) GenErc2335BlsPvKey() (*Erc2335BlsPvKey, error) {

	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate encryption key using PBKDF2
	dklen := 32
	c := 262144 // iterations

	var dk []byte
	if len(k.password) == 0 {
		dk = pbkdf2.Key(nil, salt, c, dklen, sha256.New)
	} else {
		dk = pbkdf2.Key([]byte(k.password), salt, c, dklen, sha256.New)
	}

	// Generate random IV for AES
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate iv: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Encrypt private key
	privKeyBytes := k.privKey
	ciphertext := make([]byte, len(privKeyBytes))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, privKeyBytes)

	// Generate checksum
	h := sha256.New()
	h.Write(append(dk[16:32], privKeyBytes...))
	checksum := h.Sum(nil)

	// Create keystore object
	keystore := &Erc2335BlsPvKey{
		Description: "BLS-12381 private key",
		Path:        "m/12381/60/0/0",
		UUID:        uuid.New().String(),
		Version:     4,
		Pubkey:      hex.EncodeToString(k.pubKey.Bytes()),
	}

	// Initialize nested structs
	keystore.Crypto.KDF.Function = "pbkdf2"
	keystore.Crypto.KDF.Params.Dklen = dklen
	keystore.Crypto.KDF.Params.C = c
	keystore.Crypto.KDF.Params.Prf = "hmac-sha256"
	keystore.Crypto.KDF.Params.Salt = hex.EncodeToString(salt)
	keystore.Crypto.KDF.Message = ""

	keystore.Crypto.Checksum.Function = "sha256"
	keystore.Crypto.Checksum.Params = make(map[string]interface{})
	keystore.Crypto.Checksum.Message = hex.EncodeToString(checksum)

	keystore.Crypto.Cipher.Function = "aes-128-ctr"
	keystore.Crypto.Cipher.Params.IV = hex.EncodeToString(iv)
	keystore.Crypto.Cipher.Message = hex.EncodeToString(ciphertext)

	return keystore, nil
}

// Return BLS key structure via password in ERC2335 structure.
func (k *Erc2335BlsPvKey) DecryptErc2335BlsPvKey(password string) (bls12381.PrivateKey, error) {
	// Decode salt
	salt, err := hex.DecodeString(k.Crypto.KDF.Params.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Generate decryption key
	dk := pbkdf2.Key([]byte(password), salt, k.Crypto.KDF.Params.C,
		k.Crypto.KDF.Params.Dklen, sha256.New)

	// Verify checksum
	ciphertext, err := hex.DecodeString(k.Crypto.Cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Decode IV
	iv, err := hex.DecodeString(k.Crypto.Cipher.Params.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Decrypt private key
	privKeyBytes := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(privKeyBytes, ciphertext)

	// Verify checksum
	h := sha256.New()
	h.Write(append(dk[16:32], privKeyBytes...))
	checksum := h.Sum(nil)
	expectedChecksum, err := hex.DecodeString(k.Crypto.Checksum.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checksum: %w", err)
	}

	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, fmt.Errorf("invalid password: checksum mismatch")
	}

	// Create private key from bytes
	return bls12381.PrivateKey(privKeyBytes), nil
}

// func (k *Erc2335BlsPvKey) DecryptErc2335BlsPvKey(filePath, password string) (BlsPvKey, error) {
// 	// Decode salt
// 	salt, err := hex.DecodeString(k.Crypto.KDF.Params.Salt)
// 	if err != nil {
// 		return BlsPvKey{}, fmt.Errorf("failed to decode salt: %w", err)
// 	}

// 	// Generate decryption key
// 	dk := pbkdf2.Key([]byte(password), salt, k.Crypto.KDF.Params.C,
// 		k.Crypto.KDF.Params.Dklen, sha256.New)

// 	// Verify checksum
// 	ciphertext, err := hex.DecodeString(k.Crypto.Cipher.Message)
// 	if err != nil {
// 		return BlsPvKey{}, fmt.Errorf("failed to decode ciphertext: %w", err)
// 	}

// 	// Decode IV
// 	iv, err := hex.DecodeString(k.Crypto.Cipher.Params.IV)
// 	if err != nil {
// 		return BlsPvKey{}, fmt.Errorf("failed to decode IV: %w", err)
// 	}

// 	// Create AES cipher
// 	block, err := aes.NewCipher(dk)
// 	if err != nil {
// 		return BlsPvKey{}, fmt.Errorf("failed to create AES cipher: %w", err)
// 	}

// 	// Decrypt private key
// 	privKeyBytes := make([]byte, len(ciphertext))
// 	stream := cipher.NewCTR(block, iv)
// 	stream.XORKeyStream(privKeyBytes, ciphertext)

// 	// Verify checksum
// 	h := sha256.New()
// 	h.Write(append(dk[16:32], privKeyBytes...))
// 	checksum := h.Sum(nil)
// 	expectedChecksum, err := hex.DecodeString(k.Crypto.Checksum.Message)
// 	if err != nil {
// 		return BlsPvKey{}, fmt.Errorf("failed to decode checksum: %w", err)
// 	}

// 	if !bytes.Equal(checksum, expectedChecksum) {
// 		return BlsPvKey{}, fmt.Errorf("invalid password: checksum mismatch")
// 	}

// 	return BlsPvKey{
// 		pubKey:   bls12381.PrivateKey(privKeyBytes).PubKey(),
// 		privKey:  bls12381.PrivateKey(privKeyBytes),
// 		filePath: filePath,
// 		password: password,
// 	}, nil
// }
