package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

var loghook = new(logrustest.Hook)

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

func init() {
	setupTestLogger()
}

func setupDB(config *Config) database {
	newDb := new(acmedb)
	if *postgres {
		config.Database.Engine = "postgres"
		err := newDb.Init("postgres", "postgres://acmedns:acmedns@localhost/acmedns")
		if err != nil {
			fmt.Println("PostgreSQL integration tests expect database \"acmedns\" running in localhost, with username and password set to \"acmedns\"")
			os.Exit(1)
		}
	} else {
		config.Database.Engine = "sqlite3"
		_ = newDb.Init("sqlite3", ":memory:")
	}
	return newDb
}

func setupDNSServer(config *Config, db database) (*DNSServer, func() error) {
	dnsserver := NewDNSServer(db, config.DNS.Listen, config.DNS.Proto, config.DNS.Domain)
	dnsserver.ParseRecords(config)

	// Make sure that the server has finished starting up before continuing
	var wg sync.WaitGroup
	wg.Add(1)
	dnsserver.Server.NotifyStartedFunc = wg.Done
	go dnsserver.Start(make(chan error, 1))
	wg.Wait()

	return dnsserver, dnsserver.Server.Shutdown
}

func setupConfig() *Config {
	return &Config{
		DNS: dnsConfig{
			Domain:        "auth.example.org",
			Listen:        "127.0.0.1:15353",
			Proto:         "udp",
			NSName:        "ns1.auth.example.org",
			NSAdmin:       "admin.example.org",
			StaticRecords: records,
		},
		Database: dbConfig{
			Engine:     "sqlite3",
			Connection: ":memory:",
		},
		API: apiConfig{
			Listen:     "127.0.0.1:8080",
			TLS:        false,
			UseHeader:  false,
			HeaderName: "X-Forwarded-For",
		},
	}
}

func setupTestLogger() {
	log.SetOutput(ioutil.Discard)
	log.AddHook(loghook)
}

func loggerHasEntryWithMessage(message string) bool {
	for _, v := range loghook.Entries {
		if v.Message == message {
			return true
		}
	}
	return false
}
