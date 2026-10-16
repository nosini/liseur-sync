package mirror

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// UserTransport bounds user-selected peers to public networks unless the
// operator explicitly permits an origin. Resolve and check at dial time,
// then dial the checked IP so DNS rebinding cannot bypass the check.
// No environment proxy is used: it could resolve the name differently.
func UserTransport(baseURL string, allowedOrigins []string) *http.Transport {
	allowed := false
	u, _ := url.Parse(baseURL)
	if u != nil {
		for _, origin := range allowedOrigins {
			a, err := url.Parse(origin)
			if err == nil && a.Scheme == u.Scheme && strings.EqualFold(a.Host, u.Host) && a.User == nil && (a.Path == "" || a.Path == "/") && a.RawQuery == "" && a.Fragment == "" {
				allowed = true
			}
		}
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("mirror host has no addresses")
		}
		for _, ip := range ips {
			if !allowed && !publicAddress(ip) {
				return nil, errors.New("private mirror addresses require an operator entry in mirror_allowed_origins")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	return t
}

var reservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2001::/32"),
}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedNetworks {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
