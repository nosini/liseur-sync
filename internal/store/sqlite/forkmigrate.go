package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

// forkUserMirrorsVersion is the schema version the nosini fork recorded
// for its user_mirrors migration. The fork appended it after
// workTranslationStamps, the slot upstream later gave to furthestFloor,
// so a database that ran the fork claims a version whose upstream
// migration it never applied.
const forkUserMirrorsVersion = 20

// adoptForkSchema brings a database that ran the fork back onto
// upstream's numbering before migrations run, and returns the version
// that is actually applied. The fork's version row is dropped, so the
// upstream migrations from that slot on run as on any other database,
// and its table is kept under another name: the personal mirror
// settings sealed in it stay for a later port of that feature, and no
// upstream migration creates or reads a table of that name.
//
// Any other version alongside the table is a history this does not
// know, and it is refused rather than guessed at.
func adoptForkSchema(ctx context.Context, tx *sql.Tx, applied int) (int, error) {
	var tables int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'user_mirrors'`).Scan(&tables); err != nil {
		return 0, err
	}
	if tables == 0 {
		return applied, nil
	}
	if applied != forkUserMirrorsVersion {
		return 0, fmt.Errorf(
			"the database has the fork's user_mirrors table at schema version %d, not %d; refusing to migrate it",
			applied, forkUserMirrorsVersion)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM schema_migrations WHERE version = ?`, forkUserMirrorsVersion); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`ALTER TABLE user_mirrors RENAME TO fork_user_mirrors`); err != nil {
		return 0, err
	}
	return forkUserMirrorsVersion - 1, nil
}
