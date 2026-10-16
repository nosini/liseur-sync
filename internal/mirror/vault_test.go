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
	if err != nil || info.Mode().Perm() != 0600 {
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
