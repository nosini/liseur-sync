package mirror

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chmouel/liseur-sync/internal/config"
)

func TestVaultPersistsAndAuthenticatesTheAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirror.key")
	v := &Vault{Path: path}
	m := config.Default().Mirror
	m.RemotePassword = "private-peer-password"
	sealed, err := v.Seal("alice", m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, m.RemotePassword) {
		t.Fatal("plaintext credential in storage")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions: %v %v", info, err)
	}
	restarted := &Vault{Path: path, RequireExisting: true}
	got, err := restarted.Open("alice", sealed)
	if err != nil || got != m {
		t.Fatalf("restart roundtrip: %+v %v", got, err)
	}
	if _, err := restarted.Open("bob", sealed); err == nil {
		t.Fatal("ciphertext transferred to another account")
	}
	if _, err := restarted.Open("alice", sealed[:len(sealed)/2]); err == nil {
		t.Fatal("damaged ciphertext accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Seal("bob", m); err == nil {
		t.Fatal("lost key was silently replaced")
	}
	if _, err := restarted.Seal("bob", m); err == nil {
		t.Fatal("restart with existing settings replaced a lost key")
	}
}

// TestVaultTargetHashFoldsSpellings. The digest is what the store's
// unique index compares, so two spellings of one remote account must
// give one digest, and another vault's key must give another.
func TestVaultTargetHashFoldsSpellings(t *testing.T) {
	v := &Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
	a := config.MirrorConfig{BaseURL: "https://Sync.Example:443/", RemoteUser: "Reader"}
	b := config.MirrorConfig{BaseURL: "https://sync.example", RemoteUser: "reader"}
	c := config.MirrorConfig{BaseURL: "https://sync.example", RemoteUser: "other"}
	ha, err := v.TargetHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := v.TargetHash(b)
	hc, _ := v.TargetHash(c)
	if ha != hb || ha == hc {
		t.Fatalf("digests: %s %s %s", ha, hb, hc)
	}
	other := &Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
	if ho, _ := other.TargetHash(a); ho == ha {
		t.Fatal("the digest does not depend on the key")
	}
	if strings.Contains(ha, "sync.example") {
		t.Fatal("the digest names the peer")
	}
}

// TestKeyPathDefaults puts the key beside the data it protects.
func TestKeyPathDefaults(t *testing.T) {
	c := config.Default()
	c.Database.URL = "/data/liseur-sync.db"
	if got := KeyPath(c); got != "/data/mirror.key" {
		t.Fatalf("sqlite: %s", got)
	}
	c.Database.Driver = "postgres"
	c.Content.CacheDir = "/var/lib/liseur/cache/"
	if got := KeyPath(c); got != "/var/lib/liseur/mirror.key" {
		t.Fatalf("postgres: %s", got)
	}
	c.MirrorKeyFile = "/secrets/key"
	if got := KeyPath(c); got != "/secrets/key" {
		t.Fatalf("explicit: %s", got)
	}
}
