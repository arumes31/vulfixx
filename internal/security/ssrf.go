package security

import (
	"net"
	"net/netip"
	"os"
)

// IsIPSafe checks if an IP is safe for outbound requests, blocking loopback,
// private, link-local, and unspecified addresses unless TEST_MODE is enabled.
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

	isInternal := addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()
	if isInternal {
		return os.Getenv("TEST_MODE") == "1"
	}

	return true
}
