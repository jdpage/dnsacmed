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

func setupDB(config *DNSConfig) database {
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

func setupDNSServer(config *DNSConfig, db database) (*DNSServer, func() error) {
	dnsserver := NewDNSServer(db, config.General.Listen, config.General.Proto, config.General.Domain)
	dnsserver.ParseRecords(*config)

	// Make sure that the server has finished starting up before continuing
	var wg sync.WaitGroup
	wg.Add(1)
	dnsserver.Server.NotifyStartedFunc = wg.Done
	go dnsserver.Start(make(chan error, 1))
	wg.Wait()

	return dnsserver, dnsserver.Server.Shutdown
}

func setupConfig() *DNSConfig {
	var dbcfg = dbsettings{
		Engine:     "sqlite3",
		Connection: ":memory:",
	}

	var generalcfg = general{
		Domain:        "auth.example.org",
		Listen:        "127.0.0.1:15353",
		Proto:         "udp",
		Nsname:        "ns1.auth.example.org",
		Nsadmin:       "admin.example.org",
		StaticRecords: records,
	}

	var httpapicfg = httpapi{
		Domain:     "",
		Port:       "8080",
		TLS:        "none",
		UseHeader:  false,
		HeaderName: "X-Forwarded-For",
	}

	var dnscfg = DNSConfig{
		Database: dbcfg,
		General:  generalcfg,
		API:      httpapicfg,
	}

	return &dnscfg
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
