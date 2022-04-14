package main

import (
	"github.com/jdpage/dnsacmed/pkg/api"
	"github.com/jdpage/dnsacmed/pkg/db"
	"github.com/jdpage/dnsacmed/pkg/dns"
	"go.uber.org/zap"
)

// DNSConfig holds the config structure
type Config struct {
	DNS      dns.Config `json:"dns"`
	Database db.Config  `json:"database"`
	API      api.Config `json:"api"`
	Logging  zap.Config `json:"logging"`
}
