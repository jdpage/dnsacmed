package api

import (
	"flag"
	"testing"

	"github.com/jdpage/dnsacmed/pkg/db"
	"github.com/jdpage/dnsacmed/pkg/dns"
	"go.uber.org/zap"
)

var (
	postgres = flag.Bool("postgres", false, "run integration tests against PostgreSQL")
)

var records = []string{
	"auth.example.org. A 192.168.1.100",
	"ns1.auth.example.org. A 192.168.1.101",
	"cn.example.org CNAME something.example.org.",
	"!''b', unparseable ",
	"ns2.auth.example.org. A 192.168.1.102",
}

func setupDB(t *testing.T, logger *zap.Logger) db.Database {
	var d db.Database
	if *postgres {
		var err error
		d, err = db.NewACMEDB(logger, db.Config{Engine: "postgres", Connection: "postgres://acmedns:acmedns@localhost/acmedns"})
		if err != nil {
			t.Fatal("PostgreSQL integration tests expect database \"acmedns\" running in localhost, with username and password set to \"acmedns\"")
		}
	} else {
		d, _ = db.NewACMEDB(logger, db.Config{Engine: "sqlite3", Connection: ":memory:"})
	}
	return d
}

/*
func setupDNSServer(config *Config, logger *zap.Logger, db db.Database) (*DNSServer, func() error) {
	dnsserver := NewDNSServer(logger, db, config.DNS.Listen, config.DNS.Proto, config.DNS.Domain)
	dnsserver.ParseRecords(config)

	// Make sure that the server has finished starting up before continuing
	var wg sync.WaitGroup
	wg.Add(1)
	dnsserver.Server.NotifyStartedFunc = wg.Done
	go dnsserver.Start(make(chan error, 1))
	wg.Wait()

	return dnsserver, dnsserver.Server.Shutdown
}
*/

func setupConfigs(useHeader bool) (Config, dns.Config) {
	config := Config{
		Listen:     "127.0.0.1:8080",
		TLS:        false,
		UseHeader:  useHeader,
		HeaderName: "X-Forwarded-For",
	}

	dnsConfig := dns.Config{
		Domain:        "auth.example.org",
		Listen:        "127.0.0.1:15353",
		Proto:         "udp",
		NSName:        "ns1.auth.example.org",
		NSAdmin:       "admin.example.org",
		StaticRecords: records,
	}

	return config, dnsConfig
}
