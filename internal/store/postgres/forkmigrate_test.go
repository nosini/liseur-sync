package postgres

import (
	"os"
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
	dsn := os.Getenv("LISEUR_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("LISEUR_PG_TEST_DSN not set")
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reset(t, s)
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
			`INSERT INTO schema_migrations(version, applied_at) VALUES ($1, $2)`,
			version, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// seedForkOp writes one native position op as the fork's schema could:
// AppendOps now names ops.kind and the columns beside it, which do not
// exist until upstream's later migrations run. The seq counter moves with
// the op, as the fork left it. Postgres keeps microseconds, so the times
// are truncated to what reads back.
func seedForkOp(t *testing.T, s *Store, u store.User, w store.Work, opID string, progression float64) store.Op {
	t.Helper()
	ctx := t.Context()
	clientTS := time.Now().UTC().Truncate(time.Microsecond)
	receivedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO seq_counters (user_id, next_seq) VALUES ($1, 2)
		 ON CONFLICT (user_id) DO UPDATE SET next_seq = 2`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO ops (user_id, seq, op_id, work_id, device_id, client_ts,
		                  progression, origin, received_at)
		 VALUES ($1, 1, $2, $3, 'phone', $4, $5, 'native', $6)`,
		u.ID, opID, w.ID, clientTS, progression, receivedAt); err != nil {
		t.Fatal(err)
	}
	return store.Op{
		UserID:      u.ID,
		Seq:         1,
		OpID:        opID,
		WorkID:      w.ID,
		DeviceID:    "phone",
		ClientTS:    clientTS,
		Progression: progression,
		Origin:      store.OriginNative,
		ReceivedAt:  receivedAt,
		Kind:        store.OpKindPosition,
	}
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
	// Today's Positions cannot read this schema until ops.kind exists, so
	// the "before" side of the comparison is the row we seeded.
	before := seedForkOp(t, s, u, w, "peak", 0.7)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO user_mirrors(user_id, sealed_config) VALUES ($1, 'sealed')`, u.ID); err != nil {
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
		`SELECT furthest_floor FROM works WHERE id = $1`, w.ID).Scan(&floor); err != nil {
		t.Fatalf("furthestFloor was not applied: %v", err)
	}
	after, err := s.PositionSnapshot(ctx, u.ID, w.ID, 1)
	if err != nil || len(after.Ops) != 1 {
		t.Fatalf("migration changed reading: before=%+v after=%+v err=%v", before, after, err)
	}
	// pgx scans a timestamptz into the server's local zone, so compare
	// the instant rather than the location pointer.
	got := after.Ops[0]
	got.ClientTS, got.ReceivedAt = got.ClientTS.UTC(), got.ReceivedAt.UTC()
	if !reflect.DeepEqual(before, got) {
		t.Fatalf("migration changed reading: before=%+v after=%+v", before, got)
	}
	var sealed string
	if err := s.db.QueryRowContext(ctx,
		`SELECT sealed_config FROM fork_user_mirrors WHERE user_id = $1`, u.ID).Scan(&sealed); err != nil || sealed != "sealed" {
		t.Fatalf("the fork's settings were not kept: %q %v", sealed, err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pg_tables WHERE tablename = 'user_mirrors'`).Scan(&count); err != nil || count != 0 {
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

// TestForkLedgerAdoptsTheForkTable follows the fork's sealed settings
// through every state a deployment can be in: the fork itself, a build
// that only renamed the table (no ledger yet), and a fresh database. Each
// ends with the same table, the target column and one ledger row, and a
// restart changes nothing.
func TestForkLedgerAdoptsTheForkTable(t *testing.T) {
	ctx := t.Context()
	cases := map[string]func(t *testing.T) (*Store, bool){
		"fork": func(t *testing.T) (*Store, bool) {
			s := forkDatabase(t, forkUserMirrorsVersion)
			u := storetest.MkUser(t, s, "fork-reader")
			if _, err := s.db.ExecContext(ctx,
				`INSERT INTO user_mirrors(user_id, sealed_config) VALUES ($1, 'sealed')`, u.ID); err != nil {
				t.Fatal(err)
			}
			return s, true
		},
		"renamed": func(t *testing.T) (*Store, bool) {
			s := forkDatabase(t, forkUserMirrorsVersion)
			u := storetest.MkUser(t, s, "fork-reader")
			if _, err := s.db.ExecContext(ctx,
				`INSERT INTO user_mirrors(user_id, sealed_config) VALUES ($1, 'sealed')`, u.ID); err != nil {
				t.Fatal(err)
			}
			// What the build before the ledger did, and nothing more.
			if _, err := s.db.ExecContext(ctx,
				`DELETE FROM schema_migrations WHERE version = $1`, forkUserMirrorsVersion); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx,
				`ALTER TABLE user_mirrors RENAME TO fork_user_mirrors`); err != nil {
				t.Fatal(err)
			}
			return s, true
		},
		"fresh": func(t *testing.T) (*Store, bool) {
			return freshDatabase(t), false
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			s, hasRow := build(t)
			for range 2 {
				if err := s.Migrate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			var ledger, maxVersion int
			if err := s.db.QueryRowContext(ctx,
				`SELECT COUNT(*), COALESCE(MAX(version), 0) FROM fork_migrations`).Scan(&ledger, &maxVersion); err != nil {
				t.Fatal(err)
			}
			if ledger != len(forkMigrations) || maxVersion != len(forkMigrations) {
				t.Fatalf("fork_migrations: %d rows up to %d, want %d", ledger, maxVersion, len(forkMigrations))
			}
			var count int
			if err := s.db.QueryRowContext(ctx,
				`SELECT COUNT(*), COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&count, &maxVersion); err != nil {
				t.Fatal(err)
			}
			if count != len(migrations) || maxVersion != len(migrations) {
				t.Fatalf("schema_migrations: %d rows up to %d, want %d", count, maxVersion, len(migrations))
			}
			rows, err := s.ListPersonalMirrors(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if hasRow && (len(rows) != 1 || rows[0].SealedConfig != "sealed" || rows[0].TargetHash != "") {
				t.Fatalf("the fork's row: %+v", rows)
			}
			if !hasRow && len(rows) != 0 {
				t.Fatalf("a fresh database has rows: %+v", rows)
			}
		})
	}
}

// TestALaterUpstreamUserMirrorsTableIsNotTheForks. Once the ledger exists,
// a user_mirrors table is upstream's, whatever version it arrives at, and
// the fork's repair must neither rename it nor refuse to start.
func TestALaterUpstreamUserMirrorsTableIsNotTheForks(t *testing.T) {
	ctx := t.Context()
	s := freshDatabase(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE user_mirrors (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("an upstream user_mirrors table stopped the start: %v", err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pg_tables WHERE tablename = 'user_mirrors'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("upstream's table was moved: %d %v", count, err)
	}
}

// freshDatabase is an empty schema on the test server, nothing migrated.
func freshDatabase(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("LISEUR_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("LISEUR_PG_TEST_DSN not set")
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	reset(t, s)
	return s
}
