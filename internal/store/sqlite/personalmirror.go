package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/chmouel/liseur-sync/internal/store"
)

func (s *Store) PersonalMirror(ctx context.Context, userID string) (store.PersonalMirror, error) {
	m := store.PersonalMirror{UserID: userID}
	var target sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT sealed_config, target_hash FROM fork_user_mirrors WHERE user_id = ?`,
		userID).Scan(&m.SealedConfig, &target)
	if errors.Is(err, sql.ErrNoRows) {
		return m, store.ErrNotFound
	}
	m.TargetHash = target.String
	return m, err
}

func (s *Store) PutPersonalMirror(ctx context.Context, m store.PersonalMirror) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO fork_user_mirrors (user_id, sealed_config, target_hash) VALUES (?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET
    sealed_config = excluded.sealed_config, target_hash = excluded.target_hash`,
		m.UserID, m.SealedConfig, nullIfEmpty(m.TargetHash))
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	return err
}

func (s *Store) DeletePersonalMirror(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fork_user_mirrors WHERE user_id = ?`, userID)
	return err
}

// ListPersonalMirrors is a trusted background-job lookup, like UserIDs.
func (s *Store) ListPersonalMirrors(ctx context.Context) ([]store.PersonalMirror, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, sealed_config, target_hash FROM fork_user_mirrors ORDER BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.PersonalMirror
	for rows.Next() {
		var m store.PersonalMirror
		var target sql.NullString
		if err := rows.Scan(&m.UserID, &m.SealedConfig, &target); err != nil {
			return nil, err
		}
		m.TargetHash = target.String
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) SetPersonalMirrorTarget(ctx context.Context, userID, sealedConfig, targetHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE fork_user_mirrors SET target_hash = ? WHERE user_id = ? AND sealed_config = ?`,
		nullIfEmpty(targetHash), userID, sealedConfig)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	return err
}

func nullIfEmpty(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}
