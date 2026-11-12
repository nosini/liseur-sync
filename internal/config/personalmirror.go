package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PersonalMirrorName is the name every personal mirror runs under
// (ADR-F001). The name keys a mirror's cursors per account and prefixes
// the device positions from its peer are filed under, so it must never
// be one an operator's entry for the same account could have: a list
// entry cannot contain an underscore, and validation refuses it for the
// single [mirror] entry.
const PersonalMirrorName = "personal_mirror"

// PersonalMirrorDeviceID is the device a personal mirror writes under on
// its peer unless its saved settings already name one.
func PersonalMirrorDeviceID(userID string) string { return "liseur-sync-" + userID }

// ValidatePersonalMirror checks one account's mirror the way startup
// checks an operator's entry, after forcing what a reader does not get to
// choose: the protocol is KOReader sync, and the name is the reserved
// one. A disabled mirror only has its address checked, so a reader can
// turn one off without completing it.
func (c Config) ValidatePersonalMirror(m *MirrorConfig) error {
	m.Protocol = ProtocolKosync
	m.Name = PersonalMirrorName
	m.PeerPathPrefix, m.LocalPathPrefix = "", ""
	d := mirrorDefault()
	m.PollInterval, m.ResolveRetryInterval = d.PollInterval, d.ResolveRetryInterval
	m.ActiveDays, m.Timeout = d.ActiveDays, d.Timeout
	if !m.Enabled {
		m.BaseURL = strings.TrimSpace(m.BaseURL)
		m.RemoteUser = strings.TrimSpace(m.RemoteUser)
		return c.cleanMirrorURL(m, "mirror")
	}
	return c.validateMirrorEntry(m, "mirror", true)
}

// MirrorTargetOwner names the operator's enabled entry that already
// mirrors into the same remote account as m, if any. That entry wins
// (ADR-F001): it is configuration the server started with, and a reader's
// mirror into the same account would merge two reading histories there.
func (c Config) MirrorTargetOwner(m MirrorConfig) (string, bool) {
	key := MirrorTargetKey(m)
	for _, entry := range c.EnabledMirrors() {
		if MirrorTargetKey(entry) == key {
			return entry.Name, true
		}
	}
	return "", false
}

// validateMirrorAllowedOrigins reduces each allowed origin to scheme and
// host, which is all UserTransport compares.
func (c *Config) validateMirrorAllowedOrigins() error {
	origins := make([]string, 0, len(c.MirrorAllowedOrigins))
	for _, origin := range c.MirrorAllowedOrigins {
		u, err := url.Parse(strings.TrimSpace(origin))
		if err != nil || u.Hostname() == "" ||
			(u.Scheme != "https" && u.Scheme != "http") ||
			u.User != nil || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return fmt.Errorf("mirror_allowed_origins: %q must be an http(s) origin without credentials, path or query", origin)
		}
		origins = append(origins, strings.ToLower(u.Scheme+"://"+u.Host))
	}
	c.MirrorAllowedOrigins = origins
	if strings.TrimSpace(c.MirrorKeyFile) != c.MirrorKeyFile {
		return errors.New("mirror_key_file must not start or end with whitespace")
	}
	return nil
}
