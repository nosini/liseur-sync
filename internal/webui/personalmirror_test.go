package webui

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chmouel/liseur-sync/internal/config"
	"github.com/chmouel/liseur-sync/internal/mirror"
	"github.com/chmouel/liseur-sync/internal/store"
)

const personalMirrorPage = "/ui/settings?section=devices&view=mirror"

// kosyncPeer is a peer that checks the credential the way KOReader sync
// (or, in basic mode, Calibre-Web) does and counts every request.
func kosyncPeer(t *testing.T, user, password string, basic bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	sum := md5.Sum([]byte(password))
	key := hex.EncodeToString(sum[:])
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var ok bool
		if basic {
			u, p, has := r.BasicAuth()
			ok = has && u == user && p == password && r.Header.Get("X-Auth-Key") == ""
		} else {
			ok = r.Header.Get("X-Auth-User") == user && r.Header.Get("X-Auth-Key") == key &&
				r.Header.Get("Authorization") == ""
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":"OK"}`))
	}))
	t.Cleanup(peer.Close)
	return peer, &requests
}

func personalMirrorServer(t *testing.T, mutate func(*config.Config)) (*httptest.Server, store.Store, *mirror.Vault) {
	t.Helper()
	vault := &mirror.Vault{Path: filepath.Join(t.TempDir(), "mirror.key")}
	ts, st := testServerCfg(t, mutate, func(s *Server) { s.MirrorVault = vault })
	return ts, st, vault
}

func TestReadersSetUpTheirOwnMirrors(t *testing.T) {
	for _, mode := range []string{"key", "basic"} {
		t.Run(mode, func(t *testing.T) {
			password := "peer-password-unique"
			sum := md5.Sum([]byte(password))
			key := hex.EncodeToString(sum[:])
			peer, requests := kosyncPeer(t, "remote-alice", password, mode == "basic")
			ts, st, vault := personalMirrorServer(t, func(c *config.Config) {
				c.MirrorAllowedOrigins = []string{peer.URL}
			})
			bob := mkTarget(t, st, "bob")
			alice := loginCookie(t, ts)
			code, body := page(t, ts, alice, personalMirrorPage)
			if code != http.StatusOK || !strings.Contains(body, "Save and test connection") {
				t.Fatalf("settings %d: %s", code, body)
			}
			// Fields naming another account or protocol are ignored.
			form := url.Values{
				"csrf": {extractCSRF(t, body)}, "enabled": {"on"},
				"base_url": {peer.URL}, "remote_user": {"remote-alice"},
				"remote_password": {password}, "auth": {mode},
				"account": {"bob"}, "user_id": {bob.ID}, "protocol": {"bookorbit"},
			}
			code, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if code != http.StatusOK || !strings.Contains(body, "connection tested") {
				t.Fatalf("save %d: %s", code, body)
			}
			if strings.Contains(body, password) || strings.Contains(body, key) {
				t.Fatal("the credential came back in the page")
			}
			row, err := st.PersonalMirror(t.Context(), "u1")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(row.SealedConfig, password) || strings.Contains(row.SealedConfig, key) {
				t.Fatal("the credential is stored in the clear")
			}
			if row.TargetHash == "" {
				t.Fatal("an enabled mirror holds no target")
			}
			m, err := vault.Open("u1", row.SealedConfig)
			if err != nil || m.Account != "alice" || m.Protocol != config.ProtocolKosync ||
				m.Name != config.PersonalMirrorName || m.DeviceID != config.PersonalMirrorDeviceID("u1") || !m.Enabled {
				t.Fatalf("saved settings: %+v %v", m, err)
			}
			if mode == "basic" && (m.RemotePassword != password || m.RemoteKey != "") {
				t.Fatal("the Basic password was not kept")
			}
			if mode == "key" && (m.RemoteKey != key || m.RemotePassword != "") {
				t.Fatal("the KOReader key was not kept, or the password was")
			}
			if _, err := st.PersonalMirror(t.Context(), bob.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the form wrote to another account: %v", err)
			}

			// Bob sees his own empty page, whatever he asks for.
			bobCookie := loginCookieAs(t, ts, "bob", "bobs-password")
			_, body = page(t, ts, bobCookie, personalMirrorPage+"&user=u1")
			if strings.Contains(body, "remote-alice") || strings.Contains(body, peer.URL) {
				t.Fatal("another account's mirror was shown")
			}
			_, body = page(t, ts, alice, personalMirrorPage)
			if !strings.Contains(body, "remote-alice") || strings.Contains(body, key) || strings.Contains(body, password) {
				t.Fatalf("the owner's page: %s", body)
			}

			// A blank password keeps the credential for the same peer.
			form.Set("remote_password", "")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "connection tested") {
				t.Fatalf("a blank password lost the credential: %s", body)
			}
			// Turning it off does not test, and frees the target.
			form.Del("enabled")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "turned off") || requests.Load() != 2 {
				t.Fatalf("disable: requests=%d: %s", requests.Load(), body)
			}
			if row, _ := st.PersonalMirror(t.Context(), "u1"); row.TargetHash != "" {
				t.Fatal("a disabled mirror holds its target")
			}
			// A new address never receives the saved credential.
			form.Set("enabled", "on")
			form.Set("base_url", peer.URL+"/other")
			_, body = postForm(t, ts, alice, "/ui/settings/mirror", form)
			if !strings.Contains(body, "is required") || requests.Load() != 2 {
				t.Fatalf("the credential went to a new address: %s", body)
			}

			form.Set("csrf", "wrong")
			if code, _ := postForm(t, ts, alice, "/ui/settings/mirror", form); code != http.StatusForbidden {
				t.Fatalf("CSRF: %d", code)
			}
			if code, _ := postForm(t, ts, nil, "/ui/settings/mirror", form); code == http.StatusOK {
				t.Fatal("an anonymous save was accepted")
			}
			if code, _ := postForm(t, ts, bobCookie, "/ui/settings/mirror/delete",
				url.Values{"csrf": {"wrong"}}); code != http.StatusForbidden {
				t.Fatalf("delete CSRF: %d", code)
			}

			// Bob removing his (absent) mirror leaves Alice's alone.
			_, body = page(t, ts, bobCookie, personalMirrorPage)
			postForm(t, ts, bobCookie, "/ui/settings/mirror/delete", url.Values{"csrf": {extractCSRF(t, body)}})
			if _, err := st.PersonalMirror(t.Context(), "u1"); err != nil {
				t.Fatalf("bob's delete reached alice: %v", err)
			}
			_, body = page(t, ts, alice, personalMirrorPage)
			_, body = postForm(t, ts, alice, "/ui/settings/mirror/delete", url.Values{"csrf": {extractCSRF(t, body)}})
			if !strings.Contains(body, "Mirror removed") {
				t.Fatalf("delete: %s", body)
			}
			if _, err := st.PersonalMirror(t.Context(), "u1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the row survived its removal: %v", err)
			}
		})
	}
}

// TestPersonalMirrorRefusesAPrivatePeerWithoutPermission. A reader's
// address is not the operator's decision, so a private one is never
// dialled unless the operator allowed its origin.
func TestPersonalMirrorRefusesAPrivatePeerWithoutPermission(t *testing.T) {
	peer, requests := kosyncPeer(t, "reader", "secret", true)
	ts, st, _ := personalMirrorServer(t, nil)
	cookie := loginCookie(t, ts)
	_, body := page(t, ts, cookie, personalMirrorPage)
	_, body = postForm(t, ts, cookie, "/ui/settings/mirror", url.Values{
		"csrf": {extractCSRF(t, body)}, "enabled": {"on"}, "auth": {"basic"},
		"base_url": {peer.URL}, "remote_user": {"reader"}, "remote_password": {"secret"},
	})
	if !strings.Contains(body, "private network") || requests.Load() != 0 {
		t.Fatalf("a private peer was reached: %s", body)
	}
	if _, err := st.PersonalMirror(t.Context(), "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a failed connection was saved: %v", err)
	}
}

// TestPersonalMirrorsNeverShareARemoteAccountAcrossReaders. Two local
// accounts mirroring into one remote account would merge their reading
// there, so the second is refused, whether the first is a reader's
// mirror or the operator's.
func TestPersonalMirrorsNeverShareARemoteAccountAcrossReaders(t *testing.T) {
	peer, _ := kosyncPeer(t, "shared", "secret", false)
	operator, _ := kosyncPeer(t, "op", "op-secret", false)
	ts, st, _ := personalMirrorServer(t, func(c *config.Config) {
		c.MirrorAllowedOrigins = []string{peer.URL, operator.URL}
		c.Mirrors = []config.MirrorConfig{{
			Enabled: true, Name: "operator", BaseURL: operator.URL, Account: "alice",
			RemoteUser: "op", RemoteKey: "k", DeviceID: "liseur-sync",
		}}
	})
	mkTarget(t, st, "bob")
	save := func(cookie *http.Cookie, base, user, password string) string {
		t.Helper()
		_, body := page(t, ts, cookie, personalMirrorPage)
		_, body = postForm(t, ts, cookie, "/ui/settings/mirror", url.Values{
			"csrf": {extractCSRF(t, body)}, "enabled": {"on"}, "auth": {"key"},
			"base_url": {base}, "remote_user": {user}, "remote_password": {password},
		})
		return body
	}
	alice := loginCookie(t, ts)
	bob := loginCookieAs(t, ts, "bob", "bobs-password")
	if body := save(alice, peer.URL, "shared", "secret"); !strings.Contains(body, "connection tested") {
		t.Fatalf("alice: %s", body)
	}
	// One spelling or another, it is the same remote account.
	if body := save(bob, peer.URL+"/", "shared", "secret"); !strings.Contains(body, "already mirrors into that remote account") {
		t.Fatalf("bob took alice's remote account: %s", body)
	}
	if body := save(bob, operator.URL, "op", "op-secret"); !strings.Contains(body, "already mirrors into that remote account") {
		t.Fatalf("bob took the operator's remote account: %s", body)
	}
	if _, err := st.PersonalMirror(t.Context(), "bob-id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused mirror was saved: %v", err)
	}
}

// TestAdministratorsSeeOnlyTheHostOfAPersonalMirror.
func TestAdministratorsSeeOnlyTheHostOfAPersonalMirror(t *testing.T) {
	ts, st, vault := personalMirrorServer(t, nil)
	if err := st.SetUserAdmin(t.Context(), "u1", true); err != nil {
		t.Fatal(err)
	}
	bob := mkTarget(t, st, "bob")
	m := config.MirrorConfig{
		Enabled: true, BaseURL: "https://sync.example/bobs-own-path",
		RemoteUser: "bob-remote-name", RemoteKey: "bob-remote-key",
	}
	sealed, err := vault.Seal(bob.ID, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutPersonalMirror(t.Context(), store.PersonalMirror{UserID: bob.ID, SealedConfig: sealed}); err != nil {
		t.Fatal(err)
	}
	_, body := page(t, ts, loginCookie(t, ts), "/ui/settings?section=admin&view=user&user="+bob.ID)
	if !strings.Contains(body, "sync.example") {
		t.Fatalf("the host is not shown: %s", body)
	}
	for _, secret := range []string{"bob-remote-name", "bob-remote-key", "bobs-own-path"} {
		if strings.Contains(body, secret) {
			t.Fatalf("an administrator saw %q", secret)
		}
	}
}
