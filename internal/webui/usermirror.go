package webui

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/mirror"
	"github.com/chmouel/liseur-sync/internal/store"
)

// personalMirror reads only the signed-in account. Legacy settings are visible
// to their owner too, so saving the form can take over without losing a peer.
func (s *Server) personalMirror(ctx context.Context, u *store.User) (config.MirrorConfig, error) {
	row, err := s.St.UserMirror(ctx, u.ID)
	if err == nil {
		if s.MirrorVault == nil {
			return config.MirrorConfig{}, errors.New("mirror credential storage is unavailable")
		}
		m, err := s.MirrorVault.Open(u.ID, row.SealedConfig)
		if err != nil {
			return m, errors.New("Cannot open mirror credentials. Ask the operator to restore the mirror encryption key.")
		}
		return m, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return config.MirrorConfig{}, err
	}
	if s.Cfg.Mirror.Account == u.Name && s.Cfg.Mirror.Protocol != config.ProtocolBookOrbit {
		return s.Cfg.Mirror, nil
	}
	m := config.Default().Mirror
	m.Account = u.Name
	return m, nil
}

func (s *Server) handleSaveUserMirror(w http.ResponseWriter, r *http.Request, a store.AuthSession, u *store.User) {
	if !s.checkCSRF(r, a) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	render := func(f Flash) {
		if settingsRedirect(w, r, settingsMirror, "", "", f) {
			return
		}
		s.renderSettings(w, r, a, u, settingsMirror, "", "", f, false, "", false)
	}
	if s.MirrorVault == nil {
		render(Flash{Error: "Mirror credential storage is unavailable."})
		return
	}
	old, err := s.personalMirror(r.Context(), u)
	if err != nil {
		render(Flash{Error: err.Error()})
		return
	}
	m := config.Default().Mirror
	m.Account, m.Protocol, m.Name = u.Name, config.ProtocolKosync, "personal-kosync"
	m.DeviceID = "liseur-sync-" + u.ID
	m.Enabled = r.FormValue("enabled") == "on"
	m.BaseURL = strings.TrimRight(strings.TrimSpace(r.FormValue("base_url")), "/")
	m.RemoteUser = strings.TrimSpace(r.FormValue("remote_user"))
	authMode := r.FormValue("auth_mode")
	if authMode != "kosync" && authMode != "basic" {
		render(Flash{Error: "Choose KOReader key or HTTP Basic authentication."})
		return
	}
	for _, value := range []string{m.BaseURL, m.RemoteUser, r.FormValue("remote_password")} {
		if len(value) > 4096 {
			render(Flash{Error: "Mirror fields must be at most 4096 bytes."})
			return
		}
	}
	password := r.FormValue("remote_password")
	if password == "" {
		// Reuse a saved secret only for the same destination and account. A
		// changed URL must not send a previous peer's password to a new host.
		if m.BaseURL == old.BaseURL && m.RemoteUser == old.RemoteUser && (authMode == "basic") == (old.RemotePassword != "") {
			m.RemoteKey, m.RemotePassword = old.RemoteKey, old.RemotePassword
		}
	} else if authMode == "basic" {
		m.RemotePassword = password
	} else {
		sum := md5.Sum([]byte(password))
		m.RemoteKey = hex.EncodeToString(sum[:])
	}
	// Preserve the cursor/device identity when taking over an operator mirror.
	if old.BaseURL != "" && old.Protocol == config.ProtocolKosync && old.Name != "" {
		m.Name = old.Name
	}
	if old.BaseURL != "" && old.DeviceID != "" {
		m.DeviceID = old.DeviceID
	}
	check := s.Cfg
	check.Mirror = m
	if err := check.Validate(); err != nil {
		render(Flash{Error: err.Error()})
		return
	}
	m = check.Mirror
	if m.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		transport := mirror.UserTransport(m.BaseURL, s.Cfg.MirrorAllowedOrigins)
		defer transport.CloseIdleConnections()
		if err := mirror.TestUserConnection(ctx, m, transport); err != nil {
			render(Flash{Error: "The peer connection failed. Check the address, authentication and private-origin permissions."})
			return
		}
	}
	sealed, err := s.MirrorVault.Seal(u.ID, m)
	if err != nil {
		render(Flash{Error: "Cannot save mirror credentials. Ask the operator to check mirror_key_file."})
		return
	}
	if err := s.St.PutUserMirror(r.Context(), store.UserMirror{UserID: u.ID, SealedConfig: sealed}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if s.MirrorChanged != nil {
		s.MirrorChanged()
	}
	notice := "Mirror saved and disabled. Changes apply within a few seconds."
	if m.Enabled {
		notice = "Mirror saved and connection tested. Changes apply within a few seconds."
	}
	render(Flash{Notice: notice})
}
