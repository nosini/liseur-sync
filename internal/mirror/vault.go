package mirror

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/chmouel/liseur-sync/internal/config"
)

// Vault seals personal mirror settings with a key kept outside the
// database (ADR-F001). A mirror's credential is presented to a peer, so it
// cannot be hashed the way this server's own secrets are; encryption with
// a key a database dump does not contain is the closest equivalent. The
// account ID is authenticated too, so ciphertext copied from one row to
// another does not open.
//
// The key is created on the first save, so a deployment without personal
// mirrors needs no new file.
type Vault struct {
	Path string
	// RequireExisting refuses to create a key. It is set once sealed rows
	// exist, so a lost key is reported rather than silently replaced by
	// one that opens none of them.
	RequireExisting bool
	mu              sync.Mutex
}

// KeyPath is where the vault key lives: mirror_key_file when set, else
// mirror.key beside the SQLite database, or beside the cover cache for
// PostgreSQL, whose database has no directory of its own here.
func KeyPath(c config.Config) string {
	if c.MirrorKeyFile != "" {
		return c.MirrorKeyFile
	}
	if c.Database.Driver == "sqlite" {
		return filepath.Join(filepath.Dir(c.Database.URL), "mirror.key")
	}
	return filepath.Join(filepath.Dir(filepath.Clean(c.Content.CacheDir)), "mirror.key")
}

// key reads the vault key, creating it first when create is set and the
// vault allows it. The caller holds mu.
func (v *Vault) key(create bool) ([]byte, error) {
	key, err := os.ReadFile(v.Path)
	if errors.Is(err, os.ErrNotExist) && create && !v.RequireExisting {
		if err := createKey(v.Path); err != nil {
			return nil, fmt.Errorf("create mirror encryption key: %w", err)
		}
		key, err = os.ReadFile(v.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("read mirror encryption key: %w", err)
	}
	info, err := os.Stat(v.Path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("mirror encryption key must be accessible only to its owner (chmod 600)")
	}
	if len(key) != 32 {
		return nil, errors.New("mirror encryption key must contain exactly 32 bytes")
	}
	v.RequireExisting = true
	return key, nil
}

// createKey publishes a complete key atomically and never replaces one
// that already exists: a concurrent creator's key wins, and both read it.
func createKey(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mirror-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(key); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func sealingAD(userID string) []byte { return []byte("mirror-v1:" + userID) }

func aeadFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal encrypts one account's settings. The format is the fork's
// (ADR-0053 there), so rows a deployment of it wrote still open.
func (v *Vault) Seal(userID string, m config.MirrorConfig) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key, err := v.key(true)
	if err != nil {
		return "", err
	}
	aead, err := aeadFor(key)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nil, nil, raw, sealingAD(userID))), nil
}

// Open decrypts one account's settings.
func (v *Vault) Open(userID, sealed string) (config.MirrorConfig, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var m config.MirrorConfig
	key, err := v.key(false)
	if err != nil {
		return m, err
	}
	aead, err := aeadFor(key)
	if err != nil {
		return m, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return m, errors.New("invalid encrypted mirror settings")
	}
	raw, err = aead.Open(nil, nil, raw, sealingAD(userID))
	if err != nil {
		return m, errors.New("cannot decrypt mirror settings; restore the original mirror encryption key")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, errors.New("invalid mirror settings")
	}
	return m, nil
}

// TargetHash is the digest the store's unique index compares: the remote
// account a mirror writes to, folded by config.MirrorTargetKey and keyed
// with a subkey of the vault key, so the column says nothing about which
// server or remote user a reader mirrors to without that key.
func (v *Vault) TargetHash(m config.MirrorConfig) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key, err := v.key(true)
	if err != nil {
		return "", err
	}
	sub := hmac.New(sha256.New, key)
	sub.Write([]byte("mirror-target-v1"))
	mac := hmac.New(sha256.New, sub.Sum(nil))
	mac.Write([]byte(config.MirrorTargetKey(m)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
