package security

import (
	"context"
	"fmt"
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

// ResolveSafeIP resolves a hostname and returns the first safe IP address found.
func ResolveSafeIP(ctx context.Context, host string) (net.IP, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	for _, ipAddr := range ips {
		if IsIPSafe(ipAddr.IP) {
			return ipAddr.IP, nil
		}
	}

	return nil, fmt.Errorf("no safe IP found for host: %s", host)
}

// IsHostSafe resolves a hostname and returns true only if all resolved IP addresses are safe.
func IsHostSafe(ctx context.Context, host string) (bool, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false, err
	}

	if len(ips) == 0 {
		return false, fmt.Errorf("no IP addresses found for host: %s", host)
	}

	for _, ipAddr := range ips {
		if !IsIPSafe(ipAddr.IP) {
			return false, nil
		}
	}

	return true, nil
}
