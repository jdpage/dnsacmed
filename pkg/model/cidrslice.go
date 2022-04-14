package model

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

var InvalidCIDRError = errors.New("Invalid CIDR string")

// CIDRSlice is a union of CIDR ranges
type CIDRSlice []*net.IPNet

// ParseCIDRSlice parses a list of strings into a list of networks. The first error
// encountered is returned, but even in the presence of a non-nil error, all valid
// networks are returned.
func ParseCIDRSlice(cidrs []string) (CIDRSlice, error) {
	var firstErr error
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, net, err := net.ParseCIDR(canonicalizeIPv6Addr(cidr))
		if err == nil {
			nets = append(nets, net)
		} else if firstErr == nil {
			firstErr = InvalidCIDRError
		}
	}
	return nets, firstErr
}

// Contains returns true if and only if the IP is contained in the allowed set. Note
// that an empty slice is treated as allowing all IPs, rather than none.
func (c CIDRSlice) Contains(ip net.IP) bool {
	if len(c) == 0 {
		return true
	}
	for _, n := range c {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ContainsAny returns true if and only if any of the given IPs are contained in the
// allowed set.
func (c CIDRSlice) ContainsAny(ips []net.IP) bool {
	if len(ips) == 0 {
		// If no IP is provided, then access is only allowed if the slice is also empty.
		return len(c) == 0
	}
	for _, ip := range ips {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *CIDRSlice) UnmarshalJSON(data []byte) error {
	var cidrs []string
	if err := json.Unmarshal(data, &cidrs); err != nil {
		return err
	}

	var err error
	*c, err = ParseCIDRSlice(cidrs)
	return err
}

func (c CIDRSlice) MarshalJSON() ([]byte, error) {
	var cidrs []string
	for _, n := range c {
		cidrs = append(cidrs, n.String())
	}
	return json.Marshal(cidrs)
}

// canonicalizeIPv6Addr removes square brackets from an IPv6 address. It is common to
// write IPv6 addresses with brackets in the context of HTTP, but net.ParseCIDR does not
// recognize them.
func canonicalizeIPv6Addr(s string) string {
	r := strings.NewReplacer("[", "", "]", "")
	return r.Replace(s)
}
