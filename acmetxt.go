package main

import (
	"encoding/json"
	"net"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ACMETxt is the default structure for the user controlled record
type ACMETxt struct {
	Username uuid.UUID
	Password string
	ACMETxtPost
	AllowFrom cidrslice
}

// ACMETxtPost holds the DNS part of the ACMETxt struct
type ACMETxtPost struct {
	Subdomain string `json:"subdomain"`
	Value     string `json:"txt"`
}

// cidrslice is a list of allowed cidr ranges
type cidrslice []string

func (c *cidrslice) JSON() string {
	ret, _ := json.Marshal(c.ValidEntries())
	return string(ret)
}

func (c *cidrslice) isValid() error {
	for _, v := range *c {
		_, _, err := net.ParseCIDR(sanitizeIPv6addr(v))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *cidrslice) ValidEntries() []string {
	valid := []string{}
	for _, v := range *c {
		_, _, err := net.ParseCIDR(sanitizeIPv6addr(v))
		if err == nil {
			valid = append(valid, sanitizeIPv6addr(v))
		}
	}
	return valid
}

// Check if IP belongs to an allowed net
func (a ACMETxt) allowedFrom(logger *zap.Logger, ip string) bool {
	remoteIP := net.ParseIP(ip)
	// Range not limited
	if len(a.AllowFrom.ValidEntries()) == 0 {
		return true
	}
	logger.Debug("Checking if update is permitted from IP", zap.Any("ip", remoteIP))
	for _, v := range a.AllowFrom.ValidEntries() {
		_, vnet, _ := net.ParseCIDR(v)
		if vnet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

// Go through list (most likely from headers) to check for the IP.
// Reason for this is that some setups use reverse proxy in front of acme-dns
func (a ACMETxt) allowedFromList(logger *zap.Logger, ips []string) bool {
	if len(ips) == 0 {
		// If no IP provided, check if no whitelist present (everyone has access)
		return a.allowedFrom(logger, "")
	}
	for _, v := range ips {
		if a.allowedFrom(logger, v) {
			return true
		}
	}
	return false
}

func newACMETxt() (ACMETxt, error) {
	var a = ACMETxt{}
	password, err := generatePassword()
	if err != nil {
		return a, err
	}
	a.Username = uuid.New()
	a.Password = password
	a.Subdomain = uuid.New().String()
	return a, nil
}
