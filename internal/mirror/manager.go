package mirror

import (
	"context"
	"log/slog"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/store"
)

// Manager follows account settings, stopping and joining the previous worker
// before replacing it. Disabled personal settings also suppress the legacy job.
// Its store-wide lookup is trusted background work, never a request surface.
type Manager struct {
	Store store.Store
	Cfg   config.Config
	Vault *Vault
	Log   *slog.Logger
	wake  chan struct{}
}

func NewManager(st store.Store, cfg config.Config, vault *Vault) *Manager {
	return &Manager{Store: st, Cfg: cfg, Vault: vault, Log: slog.Default(), wake: make(chan struct{}, 1)}
}

func (m *Manager) Notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

type managedJob struct {
	sealed string
	cancel context.CancelFunc
	done   chan struct{}
}

func (j managedJob) stop() { j.cancel(); <-j.done }

func (m *Manager) Run(ctx context.Context) error {
	jobs := map[string]managedJob{}
	defer func() {
		for _, j := range jobs {
			j.cancel()
		}
		for _, j := range jobs {
			<-j.done
		}
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		rows, err := m.Store.ListUserMirrors(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.Log.Error("read account mirrors", "error", err)
			}
		} else {
			desired := make(map[string]store.UserMirror, len(rows)+1)
			for _, row := range rows {
				desired[row.UserID] = row
			}
			// Keep an existing operator mirror until its owner saves personal settings.
			legacy := ""
			if m.Cfg.Mirror.Enabled {
				if u, err := m.Store.UserByName(ctx, m.Cfg.Mirror.Account); err == nil {
					if _, own := desired[u.ID]; !own {
						legacy = u.ID
						desired[u.ID] = store.UserMirror{UserID: u.ID}
					}
				}
			}
			for id, j := range jobs {
				row, exists := desired[id]
				if !exists || row.SealedConfig != j.sealed {
					j.stop()
					delete(jobs, id)
				}
			}
			for id, row := range desired {
				if _, exists := jobs[id]; exists {
					continue
				}
				cfg := m.Cfg.Mirror
				if id != legacy {
					var err error
					cfg, err = m.Vault.Open(id, row.SealedConfig)
					if err != nil {
						m.Log.Error("cannot open account mirror", "user_id", id, "error", err)
						continue
					}
					// Account mirrors expose only KOReader sync. Never trust serialized
					// account names or protocol names as authority for a worker.
					if cfg.Protocol != config.ProtocolKosync {
						continue
					}
				}
				if !cfg.Enabled {
					continue
				}
				jobCtx, cancel := context.WithCancel(ctx)
				j := managedJob{sealed: row.SealedConfig, cancel: cancel, done: make(chan struct{})}
				r := &Runner{Store: m.Store, Cfg: cfg, UserID: id, Log: m.Log}
				if id != legacy {
					r.Transport = UserTransport(cfg.BaseURL, m.Cfg.MirrorAllowedOrigins)
				}
				jobs[id] = j
				go func() { defer close(j.done); _ = r.Run(jobCtx) }()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-m.wake:
		case <-ticker.C:
		}
	}
}
