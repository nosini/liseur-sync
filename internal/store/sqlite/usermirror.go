package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/chmouel/liseur-sync/internal/store"
)

func (s *Store) UserMirror(ctx context.Context, userID string) (store.UserMirror, error) {
	m := store.UserMirror{UserID: userID}
	err := s.db.QueryRowContext(ctx, `SELECT sealed_config FROM user_mirrors WHERE user_id = ?`, userID).Scan(&m.SealedConfig)
	if errors.Is(err, sql.ErrNoRows) {
		return m, store.ErrNotFound
	}
	return m, err
}

func (s *Store) PutUserMirror(ctx context.Context, m store.UserMirror) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_mirrors (user_id, sealed_config) VALUES (?, ?)
 ON CONFLICT(user_id) DO UPDATE SET sealed_config = excluded.sealed_config`, m.UserID, m.SealedConfig)
	return err
}

// ListUserMirrors is a trusted background-job lookup, like UserIDs.
func (s *Store) ListUserMirrors(ctx context.Context) ([]store.UserMirror, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, sealed_config FROM user_mirrors ORDER BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.UserMirror
	for rows.Next() {
		var m store.UserMirror
		if err := rows.Scan(&m.UserID, &m.SealedConfig); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
