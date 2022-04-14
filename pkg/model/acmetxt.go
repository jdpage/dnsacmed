package model

import (
	"crypto/rand"
	"encoding/base64"
	"regexp"

	"github.com/google/uuid"
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

func generatePassword() (string, error) {
	// 30 bytes -> 40 chr pw
	bs := make([]byte, 30)
	_, err := rand.Read(bs)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bs), nil
}
