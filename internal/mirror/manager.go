package mirror

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/store"
)

// Manager runs the personal mirrors (ADR-F001): one worker per account
// that saved an enabled one. Operator entries are not its business; they
// keep their own workers and their restart-only configuration (ADR-0061).
//
// A personal mirror changes while the server runs, so the manager re-reads
// the rows when told a save happened and on a slow timer, and replaces a
// worker whose settings changed. It cancels the old worker and waits for
// it to return before starting the new one, so two workers for one
// account never run over the same cursors.
//
// Its store-wide read is a trusted background lookup, never a request
// surface.
type Manager struct {
	Store store.Store
	Cfg   config.Config
	Vault *Vault
	Log   *slog.Logger
	// Interval is how often the rows are re-read without a Notify. Zero
	// means 15 seconds.
	Interval time.Duration

	wake chan struct{}
	mu   sync.Mutex
	jobs map[string]*personalJob
}

// NewManager builds a manager over the given vault.
func NewManager(st store.Store, cfg config.Config, vault *Vault) *Manager {
	return &Manager{
		Store: st, Cfg: cfg, Vault: vault, Log: slog.Default(),
		wake: make(chan struct{}, 1),
		jobs: map[string]*personalJob{},
	}
}

// Notify asks for the rows to be re-read now. It never blocks.
func (m *Manager) Notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// personalJob is what the manager made of one row: a running worker, a
// disabled mirror, or a refusal with its reason.
type personalJob struct {
	sealed string
	// refused is why this row has no worker; empty for a worker and for
	// a disabled mirror. retry is set for a refusal a later pass may lift
	// without the row changing: another account holding the same target.
	refused string
	retry   bool
	runner  *Runner
	cancel  context.CancelFunc
	done    chan struct{}
}

func (j *personalJob) stop() {
	if j.cancel != nil {
		j.cancel()
		<-j.done
	}
}

// PersonalStatus is what an account's settings page says about its
// mirror.
type PersonalStatus struct {
	// Running is set while a worker exists for the saved settings.
	Running bool
	// Refused says why saved, enabled settings have no worker.
	Refused string
	Status  Status
}

// Status reports on one account's mirror; false when the manager has not
// seen a row for it.
func (m *Manager) Status(userID string) (PersonalStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[userID]
	if !ok {
		return PersonalStatus{}, false
	}
	s := PersonalStatus{Refused: j.refused}
	if j.runner != nil {
		s.Running = true
		s.Status = j.runner.Status()
	}
	return s, true
}

// Run follows the rows until ctx ends, then stops every worker and waits
// for all of them.
func (m *Manager) Run(ctx context.Context) error {
	defer func() {
		m.mu.Lock()
		jobs := m.jobs
		m.jobs = map[string]*personalJob{}
		m.mu.Unlock()
		for _, j := range jobs {
			if j.cancel != nil {
				j.cancel()
			}
		}
		for _, j := range jobs {
			if j.cancel != nil {
				<-j.done
			}
		}
	}()
	interval := m.Interval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		m.reconcile(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-m.wake:
		case <-ticker.C:
		}
	}
}

// reconcile brings the workers in line with the rows.
func (m *Manager) reconcile(ctx context.Context) {
	rows, err := m.Store.ListPersonalMirrors(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log().Error("read personal mirrors", "error", err)
		}
		return
	}
	desired := make(map[string]store.PersonalMirror, len(rows))
	for _, row := range rows {
		desired[row.UserID] = row
	}
	// Only this goroutine writes jobs; the lock is for Status.
	for id, row := range desired {
		old := m.jobs[id]
		if old != nil && old.sealed == row.SealedConfig && !old.retry {
			continue
		}
		if old != nil {
			// Joined before anything replaces it: the old worker's
			// last cursor write lands before the new worker reads any.
			old.stop()
		}
		j := m.start(ctx, row)
		if j.refused != "" && (old == nil || old.refused != j.refused) {
			m.log().Warn("personal mirror not started", "user_id", id, "reason", j.refused)
		}
		m.mu.Lock()
		m.jobs[id] = j
		m.mu.Unlock()
	}
	for id, j := range m.jobs {
		if _, ok := desired[id]; ok {
			continue
		}
		j.stop()
		m.mu.Lock()
		delete(m.jobs, id)
		m.mu.Unlock()
	}
}

// start opens one row and, when it is enabled and allowed, starts its
// worker.
func (m *Manager) start(ctx context.Context, row store.PersonalMirror) *personalJob {
	j := &personalJob{sealed: row.SealedConfig}
	cfg, refused, retry := m.prepare(ctx, row)
	if refused != "" {
		j.refused, j.retry = refused, retry
		return j
	}
	if !cfg.Enabled {
		return j
	}
	jobCtx, cancel := context.WithCancel(ctx)
	j.cancel, j.done = cancel, make(chan struct{})
	j.runner = &Runner{
		Store: m.Store, Cfg: cfg, UserID: row.UserID, Log: m.log(),
		Transport: UserTransport(cfg.BaseURL, m.Cfg.MirrorAllowedOrigins),
	}
	go func() {
		defer close(j.done)
		_ = j.runner.Run(jobCtx)
	}()
	return j
}

// prepare turns a row into the settings a worker runs with, or says why
// it may not run. Nothing in a sealed row is trusted as authority: the
// account comes from the row's key, and the protocol and name are forced
// to what a personal mirror is.
func (m *Manager) prepare(ctx context.Context, row store.PersonalMirror) (config.MirrorConfig, string, bool) {
	if m.Vault == nil {
		return config.MirrorConfig{}, "mirror credential storage is unavailable", false
	}
	cfg, err := m.Vault.Open(row.UserID, row.SealedConfig)
	if err != nil {
		return cfg, err.Error(), false
	}
	u, err := m.Store.UserByID(ctx, row.UserID)
	if err != nil {
		return cfg, fmt.Sprintf("account: %v", err), true
	}
	cfg.Account = u.Name
	if cfg.DeviceID == "" {
		cfg.DeviceID = config.PersonalMirrorDeviceID(row.UserID)
	}
	if err := m.Cfg.ValidatePersonalMirror(&cfg); err != nil {
		return cfg, err.Error(), false
	}
	target := ""
	if cfg.Enabled {
		if owner, ok := m.Cfg.MirrorTargetOwner(cfg); ok {
			return cfg, fmt.Sprintf(
				"the server's mirror %q already mirrors into this remote account", owner), false
		}
		if target, err = m.Vault.TargetHash(cfg); err != nil {
			return cfg, err.Error(), false
		}
	}
	if row.TargetHash != target {
		// A row saved before the target column existed, or one whose
		// digest no longer matches what it says. The store refuses a
		// target another account holds.
		err := m.Store.SetPersonalMirrorTarget(ctx, row.UserID, row.SealedConfig, target)
		if errors.Is(err, store.ErrConflict) {
			return cfg, "another account on this server already mirrors into this remote account", true
		}
		if err != nil {
			return cfg, err.Error(), true
		}
	}
	return cfg, "", false
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}
