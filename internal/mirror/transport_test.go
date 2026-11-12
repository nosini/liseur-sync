package mirror

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPersonalMirrorRejectsPrivatePeersUnlessAllowed(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer peer.Close()
	for _, tc := range []struct {
		origins []string
		allowed bool
	}{
		{nil, false}, {[]string{peer.URL}, true}, {[]string{peer.URL + "/other"}, false}, {[]string{"https://example.com"}, false},
	} {
		tr := UserTransport(peer.URL, tc.origins)
		req, _ := http.NewRequestWithContext(context.Background(), "GET", peer.URL, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
		if (err == nil) != tc.allowed {
			t.Fatalf("origins %v: %v", tc.origins, err)
		}
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2002:7f00:1::"} {
		if publicAddress(netip.MustParseAddr(address)) {
			t.Fatalf("private address accepted: %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(address)) {
			t.Fatalf("public address rejected: %s", address)
		}
	}
}
