package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// forkMigrations are this fork's own schema changes. They are recorded in
// fork_migrations rather than schema_migrations, so upstream keeps every
// version number to itself and a later upstream migration can never land
// on a slot the fork already took (the mistake adoptForkSchema repairs).
// The same rules apply as to upstream's list: append-only, and a shipped
// entry is never edited. Tables the fork adds carry a fork_ prefix, so
// they cannot collide with a table upstream adds later either.
var forkMigrations = []string{
	personalMirrors,
}

// personalMirrors holds one sealed KOReader mirror per account
// (ADR-F001). A database that ran the fork already has the table, under
// this name since adoptForkSchema renamed it; a fresh one gets it here.
//
// target_hash is a keyed digest of the remote account an enabled mirror
// writes to. It is NULL while a mirror is disabled and for rows written
// before the column existed, until the mirror manager fills it in. The
// unique index is what keeps two local accounts from mirroring into one
// remote account, which would merge their reading through it; NULLs are
// distinct, so a disabled mirror holds nothing.
const personalMirrors = `
CREATE TABLE IF NOT EXISTS fork_user_mirrors (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sealed_config TEXT NOT NULL
);
ALTER TABLE fork_user_mirrors ADD COLUMN target_hash TEXT;
CREATE UNIQUE INDEX fork_user_mirrors_target ON fork_user_mirrors (target_hash);
`

// applyForkMigrations runs whatever fork migrations the database has not
// applied, inside the caller's migration transaction and after
// upstream's, so a fork migration may rely on every upstream table.
func applyForkMigrations(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS fork_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	var applied int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM fork_migrations`).Scan(&applied); err != nil {
		return err
	}
	for i := applied; i < len(forkMigrations); i++ {
		if _, err := tx.ExecContext(ctx, forkMigrations[i]); err != nil {
			return fmt.Errorf("fork migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO fork_migrations (version, applied_at) VALUES (?, ?)`,
			i+1, formatTime(time.Now())); err != nil {
			return err
		}
	}
	return nil
}
