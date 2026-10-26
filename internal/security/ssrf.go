package security

import (
	"net"
	"net/netip"
	"os"
)

// blockedPrefixes lists IANA special-purpose and otherwise non-public ranges
// that pass addr.IsGlobalUnicast() but must never be reachable through
// user-controlled outbound requests (webhooks).
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT / Tailscale
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments (incl. Teredo)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4 (embeds arbitrary IPv4)
	netip.MustParsePrefix("fc00::/7"),        // unique local
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
}

// IsIPSafe checks if an IP is safe for outbound requests. It is deny-by-default:
// only global unicast addresses outside all special-purpose ranges are allowed.
// Loopback, private, link-local, multicast, CGNAT, NAT64/6to4 and similar
// ranges are rejected unless TEST_MODE is enabled.
func IsIPSafe(ip net.IP) bool {
	if ip == nil {
		return false
	}

	var addr netip.Addr
	var ok bool

	if ip4 := ip.To4(); ip4 != nil {
		addr, ok = netip.AddrFromSlice(ip4)
	} else {
		addr, ok = netip.AddrFromSlice(ip)
	}

	if !ok {
		return false
	}

	if isPublicAddr(addr) {
		return true
	}
	return os.Getenv("TEST_MODE") == "1"
}

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
