package webui

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chmouel/liseur-sync/internal/auth"
	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/mirror"
	"github.com/chmouel/liseur-sync/internal/store"
)

func TestReadersSetUpTheirOwnMirrors(t *testing.T) {
	for _, mode := range []string{"kosync", "basic"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			password := "peer-password-unique"
			sum := md5.Sum([]byte(password))
			key := hex.EncodeToString(sum[:])
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/users/auth" {
					t.Errorf("path %s", r.URL.Path)
				}
				if mode == "basic" {
					user, pass, ok := r.BasicAuth()
					if !ok || user != "remote-alice" || pass != password || r.Header.Get("X-Auth-Key") != "" {
						t.Error("wrong Basic credential")
					}
				} else if r.Header.Get("X-Auth-User") != "remote-alice" || r.Header.Get("X-Auth-Key") != key || r.Header.Get("Authorization") != "" {
					t.Error("wrong kosync credential")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer peer.Close()
			vault := &mirror.Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
			var changed atomic.Int32
			ts, st := testServerCfg(t, func(c *config.Config) { c.MirrorAllowedOrigins = []string{peer.URL} }, func(s *Server) { s.MirrorVault = vault; s.MirrorChanged = func() { changed.Add(1) } })
			hash, _ := auth.HashPassword("bob-password")
			if err := st.CreateUser(t.Context(), store.User{ID: "bob", Name: "bob", Argon2Hash: hash, Timezone: "UTC", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			alice := loginCookie(t, ts)
			code, body := page(t, ts, alice, "/ui/settings?section=mirror")
			if code != 200 || !strings.Contains(body, "Mirror your reading positions") {
				t.Fatalf("settings %d: %s", code, body)
			}
			csrf := extractCSRF(t, body)
			form := url.Values{"csrf": {csrf}, "enabled": {"on"}, "base_url": {peer.URL}, "remote_user": {"remote-alice"}, "remote_password": {password}, "auth_mode": {mode}, "account": {"bob"}, "user_id": {"bob"}, "protocol": {"bookorbit"}}
			code, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if code != 200 || !strings.Contains(body, "connection tested") {
				t.Fatalf("save %d: %s", code, body)
			}
			if strings.Contains(body, password) || strings.Contains(body, key) {
				t.Fatal("credential returned in page")
			}
			row, err := st.UserMirror(t.Context(), "u1")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(row.SealedConfig, password) || strings.Contains(row.SealedConfig, key) {
				t.Fatal("credential not encrypted")
			}
			m, err := vault.Open("u1", row.SealedConfig)
			if err != nil || m.Account != "alice" || m.Protocol != config.ProtocolKosync || m.DeviceID != "liseur-sync-u1" || !m.Enabled {
				t.Fatalf("personal settings: %+v %v", m, err)
			}
			if mode == "basic" && (m.RemotePassword != password || m.RemoteKey != "") {
				t.Fatal("Basic password not retained")
			}
			if mode == "kosync" && (m.RemoteKey != key || m.RemotePassword != "") {
				t.Fatal("kosync key not retained")
			}
			if _, err := st.UserMirror(t.Context(), "bob"); err != store.ErrNotFound {
				t.Fatalf("form wrote to another user: %v", err)
			}
			bob := loginCookieAs(t, ts, "bob", "bob-password")
			_, body = page(t, ts, bob, "/ui/settings?section=mirror&user=u1")
			if strings.Contains(body, "remote-alice") || strings.Contains(body, peer.URL) {
				t.Fatal("another user's mirror was exposed")
			}
			// Blank preserves the same peer's credential; disabled saves do not test.
			form.Set("remote_password", "")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "connection tested") {
				t.Fatalf("blank lost credential: %s", body)
			}
			form.Del("enabled")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "saved and disabled") || requests.Load() != 2 || changed.Load() != 3 {
				t.Fatalf("disable/test counts: requests=%d changed=%d: %s", requests.Load(), changed.Load(), body)
			}
			// A new URL cannot receive the saved peer's credential.
			form.Set("enabled", "on")
			form.Set("base_url", peer.URL+"/new-peer")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "required") || requests.Load() != 2 {
				t.Fatalf("credential reused for changed peer: %s", body)
			}
			form.Set("csrf", "wrong")
			code, _ = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if code != http.StatusForbidden {
				t.Fatalf("CSRF: %d", code)
			}
			code, _ = postForm(t, ts, nil, "/ui/settings/mirror", form)
			if code == http.StatusOK {
				t.Fatal("anonymous mirror save accepted")
			}
		})
	}
}

func TestPersonalMirrorRejectsPrivateOriginWithoutPermission(t *testing.T) {
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer peer.Close()
	ts, st := testServerCfg(t, nil, func(s *Server) { s.MirrorVault = &mirror.Vault{Path: filepath.Join(t.TempDir(), "mirror.key")} })
	cookie := loginCookie(t, ts)
	_, body := page(t, ts, cookie, "/ui/settings?section=mirror")
	_, body = postForm(t, ts, cookie, "/ui/settings/mirror", url.Values{"csrf": {extractCSRF(t, body)}, "enabled": {"on"}, "auth_mode": {"basic"}, "base_url": {peer.URL}, "remote_user": {"reader"}, "remote_password": {"secret"}})
	if !strings.Contains(body, "connection failed") || requests.Load() != 0 {
		t.Fatalf("private peer reached: %s", body)
	}
	if _, err := st.UserMirror(t.Context(), "u1"); err != store.ErrNotFound {
		t.Fatalf("failed connection was saved: %v", err)
	}
}
