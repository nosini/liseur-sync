package mirror

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/chmouel/liseur-sync/internal/config"
)

// Vault seals recoverable peer credentials with a key kept outside the database.
// The account ID is authenticated too: copying ciphertext between users fails.
// Key creation is lazy, so deployments without personal mirrors need no new file.
type Vault struct {
	Path string
	// RequireExisting prevents a lost key from being silently replaced.
	RequireExisting bool
	mu              sync.Mutex
}

func KeyPath(c config.Config) string {
	if c.MirrorKeyFile != "" {
		return c.MirrorKeyFile
	}
	if c.Database.Driver == "sqlite" {
		return filepath.Join(filepath.Dir(c.Database.URL), "mirror.key")
	}
	return filepath.Join(filepath.Dir(c.Content.CacheDir), "mirror.key")
}

func (v *Vault) aead(create bool) (cipher.AEAD, error) {
	key, err := os.ReadFile(v.Path)
	if errors.Is(err, os.ErrNotExist) && create && !v.RequireExisting {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		// Publish a complete key atomically; never replace an existing key.
		f, err := os.CreateTemp(filepath.Dir(v.Path), ".mirror-key-*")
		if err != nil {
			return nil, fmt.Errorf("create mirror encryption key: %w", err)
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(key); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := os.Link(f.Name(), v.Path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	if errors.Is(err, os.ErrNotExist) && create && !v.RequireExisting {
		key, err = os.ReadFile(v.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("read mirror encryption key: %w", err)
	}
	info, err := os.Stat(v.Path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("mirror encryption key must be accessible only to its owner (chmod 600)")
	}
	if len(key) != 32 {
		return nil, errors.New("mirror encryption key must contain exactly 32 bytes")
	}
	v.RequireExisting = true
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (v *Vault) Seal(userID string, m config.MirrorConfig) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	aead, err := v.aead(true)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nil, nil, raw, []byte("mirror-v1:"+userID))), nil
}

func (v *Vault) Open(userID, sealed string) (config.MirrorConfig, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var m config.MirrorConfig
	aead, err := v.aead(false)
	if err != nil {
		return m, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return m, errors.New("invalid encrypted mirror settings")
	}
	raw, err = aead.Open(nil, nil, raw, []byte("mirror-v1:"+userID))
	if err != nil {
		return m, errors.New("cannot decrypt mirror settings; restore the original mirror encryption key")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, errors.New("invalid mirror settings")
	}
	return m, nil
}
