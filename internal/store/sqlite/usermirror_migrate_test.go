package sqlite

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/chmouel/liseur-sync/internal/store"
	"github.com/chmouel/liseur-sync/internal/store/storetest"
)

func TestPersonalMirrorUpgradePreservesReadingAndCursors(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := t.Context()
	through, ok := migrationsThrough("userMirrors")
	if !ok {
		t.Fatal("unknown migration")
	}
	for i, migration := range through {
		if _, err := s.db.ExecContext(ctx, migration); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, i+1, formatTime(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	u := storetest.MkUser(t, s, "existing-reader")
	w := storetest.MkWork(t, s, u, "book", "sha-book")
	if _, err := s.AppendOps(ctx, u.ID, "phone", []store.Op{{OpID: "position", WorkID: w.ID, ClientTS: time.Now(), Progression: 0.6, Origin: store.OriginNative}}); err != nil {
		t.Fatal(err)
	}
	cursor := store.MirrorCursor{WorkID: w.ID, Document: "fingerprint", PushedSeq: 1, PeerIdentity: "existing-peer"}
	if err := s.PutMirrorCursor(ctx, u.ID, "peer", cursor); err != nil {
		t.Fatal(err)
	}
	before, err := s.Positions(ctx, u.ID, w.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s.Positions(ctx, u.ID, w.ID, 50)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("reading changed: %v", err)
	}
	cursors, err := s.MirrorCursors(ctx, u.ID, "peer")
	if err != nil || !reflect.DeepEqual(cursors[w.ID], cursor) {
		t.Fatalf("cursor changed: %+v %v", cursors, err)
	}
	rows, err := s.ListUserMirrors(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("migration invented personal settings: %+v %v", rows, err)
	}
	if err := s.PutUserMirror(ctx, store.UserMirror{UserID: u.ID, SealedConfig: "ciphertext"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserMirror(ctx, u.ID); err != store.ErrNotFound {
		t.Fatalf("personal settings outlived their owner: %v", err)
	}
}
