package model

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ACMETxt is the default structure for the user controlled record
type ACMETxt struct {
	Username uuid.UUID
	Password string
	ACMETxtPost
	AllowFrom CIDRSlice
}

// ACMETxtPost holds the DNS part of the ACMETxt struct
type ACMETxtPost struct {
	Subdomain string `json:"subdomain"`
	Value     string `json:"txt"`
}

// cidrslice is a list of allowed cidr ranges
type CIDRSlice []string

func (c *CIDRSlice) JSON() string {
	ret, _ := json.Marshal(c.ValidEntries())
	return string(ret)
}

func (c *CIDRSlice) IsValid() error {
	for _, v := range *c {
		_, _, err := net.ParseCIDR(sanitizeIPv6addr(v))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CIDRSlice) ValidEntries() []string {
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
func (a ACMETxt) IsAllowedFrom(logger *zap.Logger, ip string) bool {
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
func (a ACMETxt) IsAllowedFromList(logger *zap.Logger, ips []string) bool {
	if len(ips) == 0 {
		// If no IP provided, check if no whitelist present (everyone has access)
		return a.IsAllowedFrom(logger, "")
	}
	for _, v := range ips {
		if a.IsAllowedFrom(logger, v) {
			return true
		}
	}
	return false
}

func NewACMETxt() (*ACMETxt, error) {
	password, err := generatePassword()
	if err != nil {
		return nil, err
	}
	a := new(ACMETxt)
	a.Username = uuid.New()
	a.Password = password
	a.Subdomain = uuid.New().String()
	return a, nil
}

func SanitizeString(s string) string {
	// URL safe base64 alphabet without padding as defined in ACME
	re, _ := regexp.Compile(`[^A-Za-z\-\_0-9]+`)
	return re.ReplaceAllString(s, "")
}

func sanitizeIPv6addr(s string) string {
	// Remove brackets from IPv6 addresses, net.ParseCIDR needs this
	re, _ := regexp.Compile(`[\[\]]+`)
	return re.ReplaceAllString(s, "")
}

func generatePassword() (string, error) {
	// 30 bytes -> 40 chr pw
	bs := make([]byte, 30)
	_, err := rand.Read(bs)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bs), nil
}
