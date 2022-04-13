package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/knadh/koanf"
)

func jsonError(message string) []byte {
	return []byte(fmt.Sprintf("{\"error\": \"%s\"}", message))
}

func checkConfig(k *koanf.Koanf) error {
	for _, key := range []string{
		"dns.domain",
		"dns.nsname",
		"dns.nsadmin",
		"database.engine",
		"database.connection",
	} {
		if !k.Exists(key) {
			return fmt.Errorf("Option %s is required but not provided", key)
		}
	}
	return nil
}

func sanitizeString(s string) string {
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

func sanitizeDomainQuestion(d string) string {
	dom := strings.ToLower(d)
	firstDot := strings.Index(d, ".")
	if firstDot > 0 {
		dom = dom[0:firstDot]
	}
	return dom
}

func getIPListFromHeader(header string) []string {
	iplist := []string{}
	for _, v := range strings.Split(header, ",") {
		if len(v) > 0 {
			// Ignore empty values
			iplist = append(iplist, strings.TrimSpace(v))
		}
	}
	return iplist
}
