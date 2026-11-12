package mirror

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/store"
)

// managerFixture is the sync fixture plus a second reader with a book of
// the same fingerprint, a vault and a manager over both.
type managerFixture struct {
	*syncFixture
	bob   store.User
	vault *Vault
	m     *Manager
}

func newManagerFixture(t *testing.T, cfg config.Config, peers ...*fakePeer) *managerFixture {
	t.Helper()
	f := newSyncFixture(t)
	f.read("reader-1", 0.25, time.Now().Add(-time.Hour))
	bob := store.User{ID: "u-bob", Name: "bob", Argon2Hash: "x", Timezone: "UTC", CreatedAt: time.Now()}
	if err := f.st.CreateUser(t.Context(), bob); err != nil {
		t.Fatal(err)
	}
	w := store.Work{ID: "w-bob", UserID: bob.ID, CreatedAt: time.Now()}
	if err := f.st.CreateWork(t.Context(), w,
		&store.Edition{UserID: bob.ID, SHA256: "sha-bob", WorkID: w.ID},
		[]store.Identifier{{Kind: "partial-md5", Value: fixtureDocument}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AppendOps(t.Context(), bob.ID, "phone", []store.Op{{
		OpID: "bob-1", WorkID: w.ID, ClientTS: time.Now().Add(-time.Hour),
		Progression: 0.8, Origin: store.OriginNative,
	}}); err != nil {
		t.Fatal(err)
	}
	// httptest peers are plain HTTP on loopback: both need permission.
	cfg.InsecureHTTP = true
	cfg.MirrorAllowedOrigins = []string{f.peer.URL}
	for _, p := range peers {
		cfg.MirrorAllowedOrigins = append(cfg.MirrorAllowedOrigins, p.URL)
	}
	v := &Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
	m := NewManager(f.st, cfg, v)
	m.Log = quietLog()
	m.Interval = 20 * time.Millisecond
	return &managerFixture{syncFixture: f, bob: bob, vault: v, m: m}
}

// put seals and saves settings the way the settings page does, with the
// target digest an enabled mirror carries.
func (f *managerFixture) put(userID string, c config.MirrorConfig, withTarget bool) {
	f.t.Helper()
	sealed, err := f.vault.Seal(userID, c)
	if err != nil {
		f.t.Fatal(err)
	}
	row := store.PersonalMirror{UserID: userID, SealedConfig: sealed}
	if withTarget && c.Enabled {
		if row.TargetHash, err = f.vault.TargetHash(c); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := f.st.PutPersonalMirror(f.t.Context(), row); err != nil {
		f.t.Fatal(err)
	}
	f.m.Notify()
}

func (f *managerFixture) personal(peer *fakePeer) config.MirrorConfig {
	return config.MirrorConfig{
		Enabled: true, BaseURL: peer.URL,
		RemoteUser: peer.user, RemoteKey: peer.key,
	}
}

func (f *managerFixture) run(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = f.m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestPersonalMirrorsRunPerAccountAndChangeWithoutRestart(t *testing.T) {
	bobPeer := newFakePeer(t)
	f := newManagerFixture(t, config.Default(), bobPeer)
	bobCfg := f.personal(bobPeer)
	// A forged account name in the sealed settings: the row's key wins.
	bobCfg.Account = f.user.Name
	f.put(f.bob.ID, bobCfg, true)
	f.put(f.user.ID, f.personal(f.peer), true)
	f.run(t)

	waitFor(t, "both accounts to sync", func() bool {
		return len(f.peer.pushed(t)) == 1 && len(bobPeer.pushed(t)) == 1
	})
	if f.peer.pushed(t)[0].Percentage != 0.25 || bobPeer.pushed(t)[0].Percentage != 0.8 {
		t.Fatal("accounts crossed")
	}
	if got := f.peer.pushed(t)[0].DeviceID; got != config.PersonalMirrorDeviceID(f.user.ID) {
		t.Fatalf("device id %q", got)
	}

	// Disabling stops the worker, without a restart.
	off := f.personal(f.peer)
	off.Enabled = false
	f.put(f.user.ID, off, true)
	waitFor(t, "the worker to stop", func() bool {
		s, ok := f.m.Status(f.user.ID)
		return ok && !s.Running
	})
	f.read("reader-2", 0.45, time.Now())
	time.Sleep(100 * time.Millisecond)
	if len(f.peer.pushed(t)) != 1 {
		t.Fatal("a disabled mirror kept pushing")
	}
	if row, _ := f.st.PersonalMirror(t.Context(), f.user.ID); row.TargetHash != "" {
		t.Fatal("a disabled mirror holds its target")
	}

	// Re-enabling resumes it, and pointing it elsewhere replaces it.
	f.put(f.user.ID, f.personal(f.peer), true)
	waitFor(t, "the mirror to resume", func() bool { return len(f.peer.pushed(t)) == 2 })
	other := newFakePeer(t)
	other.user = "someone-else"
	f.m.Cfg.MirrorAllowedOrigins = append(f.m.Cfg.MirrorAllowedOrigins, other.URL)
	f.put(f.user.ID, f.personal(other), true)
	waitFor(t, "the new peer to receive the reading", func() bool { return len(other.pushed(t)) == 1 })
	if other.pushed(t)[0].Percentage != 0.45 {
		t.Fatal("the replacement used another account's reading")
	}

	// Removing the row stops the worker and forgets the account.
	if err := f.st.DeletePersonalMirror(t.Context(), f.bob.ID); err != nil {
		t.Fatal(err)
	}
	f.m.Notify()
	waitFor(t, "the removed mirror to go", func() bool {
		_, ok := f.m.Status(f.bob.ID)
		return !ok
	})
}

// TestPersonalMirrorsNeverShareARemoteAccount. Two local accounts
// mirroring into one remote account would merge their reading there. The
// operator's entry wins over a personal one, and between two personal
// ones the first to hold the target does, until it lets go.
func TestPersonalMirrorsNeverShareARemoteAccount(t *testing.T) {
	operatorPeer := newFakePeer(t)
	cfg := config.Default()
	cfg.Mirrors = []config.MirrorConfig{{
		Enabled: true, Name: "operator", BaseURL: operatorPeer.URL,
		Account: "reader", RemoteUser: operatorPeer.user, RemoteKey: operatorPeer.key,
	}}
	f := newManagerFixture(t, cfg, operatorPeer)

	f.put(f.bob.ID, f.personal(operatorPeer), true)
	// Alice's row predates the target column: the manager fills it in.
	f.put(f.user.ID, f.personal(f.peer), false)
	f.run(t)
	waitFor(t, "the refusal and the fill-in", func() bool {
		s, ok := f.m.Status(f.bob.ID)
		row, _ := f.st.PersonalMirror(t.Context(), f.user.ID)
		return ok && s.Refused != "" && row.TargetHash != ""
	})
	if s, _ := f.m.Status(f.bob.ID); s.Running {
		t.Fatal("a personal mirror ran into the operator's remote account")
	}
	if len(operatorPeer.pushed(t)) != 0 {
		t.Fatal("bob's reading reached the operator's peer")
	}

	// Bob now asks for Alice's target. His save has no digest yet (an old
	// row); the store refuses the fill-in, and he waits for her.
	f.put(f.bob.ID, f.personal(f.peer), false)
	waitFor(t, "the conflict to be refused", func() bool {
		s, ok := f.m.Status(f.bob.ID)
		return ok && !s.Running && s.Refused != "" &&
			s.Refused != "the server's mirror \"operator\" already mirrors into this remote account"
	})
	waitFor(t, "alice's reading to reach her peer", func() bool { return len(f.peer.pushed(t)) == 1 })
	if f.peer.pushed(t)[0].Percentage != 0.25 {
		t.Fatal("bob's reading reached alice's remote account")
	}
	if err := f.st.DeletePersonalMirror(t.Context(), f.user.ID); err != nil {
		t.Fatal(err)
	}
	f.m.Notify()
	waitFor(t, "bob to take over the freed target", func() bool {
		s, ok := f.m.Status(f.bob.ID)
		return ok && s.Running
	})
}
