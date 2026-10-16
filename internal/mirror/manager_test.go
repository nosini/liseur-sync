package mirror

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/store"
)

func TestPersonalMirrorsRunTogetherAndReplaceLegacyWithoutRestart(t *testing.T) {
	f := newSyncFixture(t)
	f.read("alice-1", 0.25, time.Now().Add(-time.Hour))
	bob := store.User{ID: "bob", Name: "bob", Argon2Hash: "x", Timezone: "UTC", CreatedAt: time.Now()}
	if err := f.st.CreateUser(t.Context(), bob); err != nil {
		t.Fatal(err)
	}
	w := store.Work{ID: "w1", UserID: bob.ID, CreatedAt: time.Now()}
	if err := f.st.CreateWork(t.Context(), w, &store.Edition{UserID: bob.ID, SHA256: "sha-bob", WorkID: w.ID}, []store.Identifier{{Kind: "partial-md5", Value: fixtureDocument}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AppendOps(t.Context(), bob.ID, "phone", []store.Op{{OpID: "bob-1", WorkID: w.ID, ClientTS: time.Now().Add(-time.Hour), Progression: 0.8, Origin: store.OriginNative}}); err != nil {
		t.Fatal(err)
	}
	bobPeer := newFakePeer(t)
	cfg := config.Default()
	cfg.Mirror = f.runnerConfig()
	cfg.MirrorAllowedOrigins = []string{f.peer.URL, bobPeer.URL}
	v := &Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
	m := NewManager(f.st, cfg, v)
	m.Log = quietLog()
	put := func(id string, c config.MirrorConfig) {
		t.Helper()
		sealed, err := v.Seal(id, c)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.st.PutUserMirror(t.Context(), store.UserMirror{UserID: id, SealedConfig: sealed}); err != nil {
			t.Fatal(err)
		}
		m.Notify()
	}
	bobCfg := f.runnerConfig()
	bobCfg.Protocol = config.ProtocolKosync
	bobCfg.BaseURL = bobPeer.URL
	// Deliberately forge the account name in storage: the immutable ID wins.
	bobCfg.Account = f.user.Name
	put(bob.ID, bobCfg)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "both accounts to sync", func() bool { return len(f.peer.pushed(t)) == 1 && len(bobPeer.pushed(t)) == 1 })
	if f.peer.pushed(t)[0].Percentage != 0.25 || bobPeer.pushed(t)[0].Percentage != 0.8 {
		t.Fatal("accounts crossed")
	}
	// A disabled personal row takes over the legacy job too.
	own := f.runnerConfig()
	own.Protocol = config.ProtocolKosync
	own.Enabled = false
	put(f.user.ID, own)
	// Wait for manager to stop the old worker using a synchronized next load.
	// The bounded poll gives the manager time even on a busy race-enabled run.
	time.Sleep(100 * time.Millisecond)
	f.read("alice-2", 0.45, time.Now())
	time.Sleep(100 * time.Millisecond)
	if len(f.peer.pushed(t)) != 1 {
		t.Fatal("legacy mirror survived personal disable")
	}
	own.Enabled = true
	put(f.user.ID, own)
	waitFor(t, "mirror to resume without restart", func() bool { return len(f.peer.pushed(t)) == 2 })
	// Editing the peer replaces the worker and resets peer-specific cursors.
	own.BaseURL = bobPeer.URL
	put(f.user.ID, own)
	waitFor(t, "new peer to receive Alice's reading", func() bool { return len(bobPeer.pushed(t)) == 2 })
	if bobPeer.pushed(t)[1].Percentage != 0.45 {
		t.Fatal("replacement used another user's reading")
	}
}
