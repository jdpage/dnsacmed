package main

import (
	"database/sql"
	"sync"

	"github.com/google/uuid"
)

// DNSConfig holds the config structure
type Config struct {
	DNS      dnsConfig `json:"dns"`
	Database dbConfig  `json:"database"`
	API      apiConfig `json:"api"`
	Logging  logConfig `json:"logging"`
}

// Config file general section
type dnsConfig struct {
	Listen        string   `json:"listen"`
	Proto         string   `json:"protocol"`
	Domain        string   `json:"domain"`
	NSName        string   `json:"nsname"`
	NSAdmin       string   `json:"nsadmin"`
	StaticRecords []string `json:"records"`
}

type dbConfig struct {
	Engine     string `json:"engine"`
	Connection string `json:"connection"`
}

// API config
type apiConfig struct {
	Listen              string `json:"listen"`
	DisableRegistration bool   `json:"disable_registration"`
	TLS                 bool   `json:"tls"`
	TLSCertPrivkey      string `json:"tls_cert_privkey"`
	TLSCertFullchain    string `json:"tls_cert_fullchain"`
	UseHeader           bool   `json:"use_header"`
	HeaderName          string `json:"header_name"`
}

// Logging config
type logConfig struct {
	Level   string `json:"level"`
	Logtype string `json:"type"`
	File    string `json:"file"`
	Format  string `json:"format"`
}

type acmedb struct {
	sync.Mutex
	DB     *sql.DB
	engine string
}

type database interface {
	Init(string, string) error
	Register(cidrslice) (ACMETxt, error)
	GetByUsername(uuid.UUID) (ACMETxt, error)
	GetTXTForDomain(string) ([]string, error)
	Update(ACMETxtPost) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
	Lock()
	Unlock()
}
