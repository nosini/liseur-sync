package config

import (
	"strings"
	"testing"
)

// TestPersonalMirrorSettingsAreForced. A reader picks a peer and a
// credential, nothing else: the protocol and the name are fixed, and the
// address is held to the same rules as an operator's.
func TestPersonalMirrorSettingsAreForced(t *testing.T) {
	c := Default()
	m := MirrorConfig{
		Enabled: true, Protocol: ProtocolBookOrbit, Name: "orbit",
		BaseURL: " https://sync.example/ ", Account: "alice",
		RemoteUser: "reader", RemoteKey: "k", DeviceID: "liseur-sync-u1",
		PollInterval: 1, PeerPathPrefix: "/x", LocalPathPrefix: "/y",
	}
	if err := c.ValidatePersonalMirror(&m); err != nil {
		t.Fatal(err)
	}
	if m.Protocol != ProtocolKosync || m.Name != PersonalMirrorName ||
		m.BaseURL != "https://sync.example" || m.PeerPathPrefix != "" ||
		m.PollInterval != mirrorDefault().PollInterval {
		t.Fatalf("not forced: %+v", m)
	}
	plain := MirrorConfig{Enabled: true, BaseURL: "http://sync.example", Account: "alice",
		RemoteUser: "reader", RemoteKey: "k", DeviceID: "d"}
	if err := c.ValidatePersonalMirror(&plain); err == nil {
		t.Fatal("plain HTTP accepted without insecure_http")
	}
	off := MirrorConfig{BaseURL: "https://user:pw@sync.example"}
	if err := c.ValidatePersonalMirror(&off); err == nil {
		t.Fatal("a credential in a disabled mirror's address was accepted")
	}
}

func TestPersonalMirrorNameIsReserved(t *testing.T) {
	c := Default()
	c.SetMirrorTableDefined(true)
	c.Mirror.Name = strings.ToUpper(PersonalMirrorName)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("the reserved name was accepted: %v", err)
	}
	if mirrorListName.MatchString(PersonalMirrorName) {
		t.Fatal("a [[mirrors]] entry could take the reserved name")
	}
}

func TestMirrorAllowedOrigins(t *testing.T) {
	c := Default()
	c.MirrorAllowedOrigins = []string{"HTTPS://Calibre.Example:8443/", "http://10.0.0.2"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.MirrorAllowedOrigins[0] != "https://calibre.example:8443" || c.MirrorAllowedOrigins[1] != "http://10.0.0.2" {
		t.Fatalf("origins: %v", c.MirrorAllowedOrigins)
	}
	for _, bad := range []string{"calibre.example", "https://x/path", "https://u:p@x", "ftp://x", "https://x?q"} {
		c := Default()
		c.MirrorAllowedOrigins = []string{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMirrorTargetOwner(t *testing.T) {
	c := Default()
	c.Mirrors = []MirrorConfig{{Enabled: true, Name: "op", BaseURL: "https://sync.example", RemoteUser: "Op"}}
	if name, ok := c.MirrorTargetOwner(MirrorConfig{BaseURL: "https://SYNC.example:443/", RemoteUser: "op"}); !ok || name != "op" {
		t.Fatalf("owner: %q %v", name, ok)
	}
	if _, ok := c.MirrorTargetOwner(MirrorConfig{BaseURL: "https://sync.example", RemoteUser: "other"}); ok {
		t.Fatal("another remote user matched")
	}
}
