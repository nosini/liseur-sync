package sqlite

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chmouel/liseur-sync/internal/store"
	"github.com/chmouel/liseur-sync/internal/store/storetest"
)

// forkUserMirrors is the fork's migration, verbatim: what a database
// that ran the fork has applied at forkUserMirrorsVersion.
const forkUserMirrors = `
CREATE TABLE user_mirrors (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sealed_config TEXT NOT NULL
);
`

// forkDatabase builds a database the way the fork left it: upstream's
// migrations up to the slot the fork took, then the fork's own, recorded
// at extraVersion.
func forkDatabase(t *testing.T, extraVersion int) *Store {
	t.Helper()
	ctx := t.Context()
	s, err := Open(filepath.Join(t.TempDir(), "fork.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	through, ok := migrationsThrough("furthestFloor")
	if !ok {
		t.Fatal("furthestFloor is no longer a known migration")
	}
	if len(through) != forkUserMirrorsVersion-1 {
		t.Fatalf("the fork shared %d migrations with upstream, not %d", forkUserMirrorsVersion-1, len(through))
	}
	// through shares migrations' backing array, so it is copied before
	// anything is appended to it.
	history := append(append([]string(nil), through...), forkUserMirrors)
	for i, migration := range history {
		version := i + 1
		if migration == forkUserMirrors {
			version = extraVersion
		}
		if _, err := s.db.ExecContext(ctx, migration); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			version, formatTime(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// TestADatabaseThatRanTheForkGetsUpstreamsMigrations. The fork recorded
// its user_mirrors table at the version upstream gave furthestFloor, so
// counting alone would skip furthestFloor forever. The upgrade has to
// apply every upstream migration, keep the reading, and keep the
// fork's sealed settings for when that feature is ported.
func TestADatabaseThatRanTheForkGetsUpstreamsMigrations(t *testing.T) {
	ctx := t.Context()
	s := forkDatabase(t, forkUserMirrorsVersion)
	u := storetest.MkUser(t, s, "existing-reader")
	w := storetest.MkWork(t, s, u, "w1", "abc123")
	if _, err := s.AppendOps(ctx, u.ID, "phone", []store.Op{
		{OpID: "peak", WorkID: w.ID, Progression: 0.7, ClientTS: time.Now(), Origin: store.OriginNative},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO user_mirrors(user_id, sealed_config) VALUES (?, 'sealed')`, u.ID); err != nil {
		t.Fatal(err)
	}
	before, err := s.Positions(ctx, u.ID, w.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}

	var count, maxVersion int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(version) FROM schema_migrations`).Scan(&count, &maxVersion); err != nil {
		t.Fatal(err)
	}
	if count != len(migrations) || maxVersion != len(migrations) {
		t.Fatalf("schema_migrations: %d rows up to %d, want %d", count, maxVersion, len(migrations))
	}
	var floor int
	if err := s.db.QueryRowContext(ctx,
		`SELECT furthest_floor FROM works WHERE id = ?`, w.ID).Scan(&floor); err != nil {
		t.Fatalf("furthestFloor was not applied: %v", err)
	}
	after, err := s.PositionSnapshot(ctx, u.ID, w.ID, 1)
	if err != nil || !reflect.DeepEqual(before, after.Ops) {
		t.Fatalf("migration changed reading: before=%+v after=%+v err=%v", before, after, err)
	}
	var sealed string
	if err := s.db.QueryRowContext(ctx,
		`SELECT sealed_config FROM fork_user_mirrors WHERE user_id = ?`, u.ID).Scan(&sealed); err != nil || sealed != "sealed" {
		t.Fatalf("the fork's settings were not kept: %q %v", sealed, err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name = 'user_mirrors'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("user_mirrors is still there: %d %v", count, err)
	}
}

// TestAForkTableAtAnUnknownVersionIsRefused. A user_mirrors table beside
// any other version is a history nobody wrote this for, so nothing is
// migrated.
func TestAForkTableAtAnUnknownVersionIsRefused(t *testing.T) {
	ctx := t.Context()
	s := forkDatabase(t, forkUserMirrorsVersion+1)
	err := s.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "user_mirrors") {
		t.Fatalf("an unknown fork history was migrated: %v", err)
	}
	var maxVersion int
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVersion); err != nil || maxVersion != forkUserMirrorsVersion+1 {
		t.Fatalf("the refused migration changed the version: %d %v", maxVersion, err)
	}
}
