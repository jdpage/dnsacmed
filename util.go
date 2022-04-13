package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
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

func generatePassword(length int) string {
	ret := make([]byte, length)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_"
	alphalen := big.NewInt(int64(len(alphabet)))
	for i := 0; i < length; i++ {
		c, _ := rand.Int(rand.Reader, alphalen)
		r := int(c.Int64())
		ret[i] = alphabet[r]
	}
	return string(ret)
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
