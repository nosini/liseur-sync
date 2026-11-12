package webui

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/mirror"
	"github.com/chmouel/liseur-sync/internal/store"
)

// A reader's own KOReader mirror (ADR-F001). Every read and write here is
// keyed by the signed-in account and nothing else: the form carries no
// account, and the page never renders a credential.

// personalMirrorFieldMax bounds every field the form sends.
const personalMirrorFieldMax = 4096

// personalMirrorView is what the Mirror page shows.
type personalMirrorView struct {
	// Available is false when the server has no vault to seal with.
	Available bool
	// Saved is set when the account has a row; Config is its settings
	// with the credential cleared.
	Saved     bool
	Config    config.MirrorConfig
	BasicAuth bool
	HasKey    bool
	// Problem is why the saved settings could not be opened.
	Problem string
	// Running, Refused and Status are the worker's state.
	Running bool
	Refused string
	Status  mirror.Status
}

// openPersonalMirror reads the account's saved settings, credential
// included; callers clear it before anything renders.
func (s *Server) openPersonalMirror(ctx context.Context, u *store.User) (config.MirrorConfig, bool, error) {
	row, err := s.St.PersonalMirror(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return config.MirrorConfig{}, false, nil
	}
	if err != nil {
		return config.MirrorConfig{}, false, err
	}
	if s.MirrorVault == nil {
		return config.MirrorConfig{}, true, errors.New("mirror credential storage is unavailable")
	}
	m, err := s.MirrorVault.Open(u.ID, row.SealedConfig)
	if err != nil {
		return config.MirrorConfig{}, true, errors.New(
			"the saved mirror settings cannot be opened; ask the administrator to restore the mirror encryption key")
	}
	return m, true, nil
}

func (s *Server) personalMirrorView(ctx context.Context, u *store.User) personalMirrorView {
	v := personalMirrorView{Available: s.MirrorVault != nil}
	m, saved, err := s.openPersonalMirror(ctx, u)
	v.Saved = saved
	if err != nil {
		v.Problem = personalMirrorError(err)
		return v
	}
	v.BasicAuth = config.MirrorBasicAuth(m)
	v.HasKey = mirrorHasCredential(m)
	m.RemoteKey, m.RemotePassword = "", ""
	v.Config = m
	if s.PersonalMirrors != nil {
		if st, ok := s.PersonalMirrors.Status(u.ID); ok {
			v.Running, v.Refused, v.Status = st.Running, st.Refused, st.Status
		}
	}
	return v
}

// personalMirrorFromForm is the mirror the form describes, on top of what
// was saved. A blank password keeps the saved credential only for the
// same peer, the same remote user and the same authentication: a changed
// address must never receive the previous peer's password.
func personalMirrorFromForm(r *http.Request, u *store.User, old config.MirrorConfig) (config.MirrorConfig, error) {
	for _, field := range []string{"base_url", "remote_user", "remote_password"} {
		if len(r.FormValue(field)) > personalMirrorFieldMax {
			return config.MirrorConfig{}, errors.New("mirror fields must be at most 4096 bytes")
		}
	}
	m := config.Default().Mirror
	m.Account = u.Name
	m.DeviceID = old.DeviceID
	if m.DeviceID == "" {
		m.DeviceID = config.PersonalMirrorDeviceID(u.ID)
	}
	m.Enabled = r.FormValue("enabled") == "on"
	m.BaseURL = strings.TrimSpace(r.FormValue("base_url"))
	m.RemoteUser = strings.TrimSpace(r.FormValue("remote_user"))
	var basic bool
	switch r.FormValue("auth") {
	case "key":
	case "basic":
		basic = true
	default:
		return config.MirrorConfig{}, errors.New("choose KOReader key or HTTP Basic authentication")
	}
	password := r.FormValue("remote_password")
	switch {
	case password == "":
		if config.MirrorRoot(m.BaseURL) == config.MirrorRoot(old.BaseURL) &&
			m.RemoteUser == old.RemoteUser && basic == config.MirrorBasicAuth(old) {
			m.RemoteKey, m.RemotePassword = old.RemoteKey, old.RemotePassword
		}
	case basic:
		m.RemotePassword = password
	default:
		sum := md5.Sum([]byte(password))
		m.RemoteKey = hex.EncodeToString(sum[:])
	}
	return m, nil
}

// savePersonalMirror validates, tests and stores the form, and says what
// to tell the reader.
func (s *Server) savePersonalMirror(r *http.Request, u *store.User) (string, error) {
	if s.MirrorVault == nil {
		return "", errors.New("mirror credential storage is unavailable")
	}
	old, _, err := s.openPersonalMirror(r.Context(), u)
	if err != nil {
		return "", err
	}
	m, err := personalMirrorFromForm(r, u, old)
	if err != nil {
		return "", err
	}
	if err := s.Cfg.ValidatePersonalMirror(&m); err != nil {
		return "", err
	}
	row := store.PersonalMirror{UserID: u.ID}
	if m.Enabled {
		if _, ok := s.Cfg.MirrorTargetOwner(m); ok {
			return "", errors.New("this server already mirrors into that remote account")
		}
		if row.TargetHash, err = s.MirrorVault.TargetHash(m); err != nil {
			return "", errors.New("cannot save mirror settings; ask the administrator to check mirror_key_file")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		transport := mirror.UserTransport(m.BaseURL, s.Cfg.MirrorAllowedOrigins)
		defer transport.CloseIdleConnections()
		if err := mirror.CheckPersonalConnection(ctx, m, transport); err != nil {
			if errors.Is(err, mirror.ErrUnauthorized) {
				return "", errors.New("the peer rejected the username or password")
			}
			return "", errors.New("the peer could not be reached; check the address. " +
				"A peer on a private network needs the administrator's permission")
		}
	}
	if row.SealedConfig, err = s.MirrorVault.Seal(u.ID, m); err != nil {
		return "", errors.New("cannot save mirror settings; ask the administrator to check mirror_key_file")
	}
	if err := s.St.PutPersonalMirror(r.Context(), row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", errors.New("another account on this server already mirrors into that remote account")
		}
		return "", err
	}
	if s.PersonalMirrors != nil {
		s.PersonalMirrors.Notify()
	}
	if m.Enabled {
		return "Mirror saved and connection tested. It starts within a few seconds.", nil
	}
	return "Mirror saved and turned off.", nil
}

func (s *Server) handleSavePersonalMirror(w http.ResponseWriter, r *http.Request, a store.AuthSession, u *store.User) {
	if !s.checkCSRF(r, a) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	notice, err := s.savePersonalMirror(r, u)
	if err != nil {
		s.renderDevices(w, r, a, u, settingsDevicesMirror, Flash{Error: personalMirrorError(err)})
		return
	}
	s.renderDevices(w, r, a, u, settingsDevicesMirror, Flash{Notice: notice})
}

func (s *Server) handleDeletePersonalMirror(w http.ResponseWriter, r *http.Request, a store.AuthSession, u *store.User) {
	if !s.checkCSRF(r, a) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.St.DeletePersonalMirror(r.Context(), u.ID); err != nil {
		s.renderDevices(w, r, a, u, settingsDevicesMirror, Flash{Error: "Could not remove the mirror."})
		return
	}
	if s.PersonalMirrors != nil {
		s.PersonalMirrors.Notify()
	}
	s.renderDevices(w, r, a, u, settingsDevicesMirror, Flash{Notice: "Mirror removed."})
}

// personalMirrorError is a refusal as the page shows it, capitalised.
func personalMirrorError(err error) string {
	msg := err.Error()
	if msg == "" {
		return msg
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

// personalMirrorHost is what an administrator may know about a reader's
// mirror: the host it goes to, never the remote user or the credential.
func (s *Server) personalMirrorHost(ctx context.Context, userID string) (host string, enabled, ok bool) {
	if s.MirrorVault == nil {
		return "", false, false
	}
	row, err := s.St.PersonalMirror(ctx, userID)
	if err != nil {
		return "", false, false
	}
	m, err := s.MirrorVault.Open(userID, row.SealedConfig)
	if err != nil {
		return "unreadable settings", false, true
	}
	if parsed, err := url.Parse(m.BaseURL); err == nil {
		host = parsed.Hostname()
	}
	return host, m.Enabled, true
}
