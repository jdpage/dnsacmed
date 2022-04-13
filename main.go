//go:build !test
// +build !test

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	log "github.com/sirupsen/logrus"
)

var defaultConfig = map[string]interface{}{
	"dns.listen":               "0.0.0.0:53",
	"dns.protocol":             "both",
	"dns.records":              []string{},
	"api.listen":               "0.0.0.0:80",
	"api.disable_registration": false,
	"api.tls":                  false,
	"api.use_header":           false,
	"api.header_name":          "X-Forwarded-For",
}

func main() {
	configPtr := flag.String("c", "", "config file location")
	flag.Parse()

	// Created files are not world writable
	syscall.Umask(0077)

	// Load defaults
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaultConfig, "."), nil); err != nil {
		panic(err)
	}

	// Read in the global config
	if *configPtr != "" {
		if err := k.Load(file.Provider(*configPtr), toml.Parser()); err != nil {
			panic(err)
		}
	} else {
		if err := k.Load(file.Provider("/etc/dnsacmed/config.toml"), toml.Parser()); err != nil {
			k.Load(file.Provider("config.toml"), toml.Parser())
		}
	}

	// Read in environment variables
	k.Load(env.Provider("DNSACMED_", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "DNSACMED_")), "_", ".", -1)
	}), nil)

	if err := checkConfig(k); err != nil {
		panic(err)
	}

	var config Config
	if err := k.UnmarshalWithConf("", &config, koanf.UnmarshalConf{Tag: "json"}); err != nil {
		panic(fmt.Errorf("Error unmarshaling config file: %w", err))
	}

	setupLogging(config.Logging.Format, config.Logging.Level)

	// Open database
	db := new(acmedb)
	if err := db.Init(config.Database.Engine, config.Database.Connection); err != nil {
		log.Errorf("Could not open database [%v]", err)
		os.Exit(1)
	} else {
		log.Info("Connected to database")
	}
	defer db.Close()

	// Error channel for servers
	errChan := make(chan error, 1)

	// DNS server
	dnsservers := make([]*DNSServer, 0)
	if strings.HasPrefix(config.DNS.Proto, "both") {
		// Handle the case where DNS server should be started for both udp and tcp
		udpProto := "udp"
		tcpProto := "tcp"
		if strings.HasSuffix(config.DNS.Proto, "4") {
			udpProto += "4"
			tcpProto += "4"
		} else if strings.HasSuffix(config.DNS.Proto, "6") {
			udpProto += "6"
			tcpProto += "6"
		}
		dnsServerUDP := NewDNSServer(db, config.DNS.Listen, udpProto, config.DNS.Domain)
		dnsservers = append(dnsservers, dnsServerUDP)
		dnsServerUDP.ParseRecords(&config)
		dnsServerTCP := NewDNSServer(db, config.DNS.Listen, tcpProto, config.DNS.Domain)
		dnsservers = append(dnsservers, dnsServerTCP)
		// No need to parse records from config again
		dnsServerTCP.Domains = dnsServerUDP.Domains
		dnsServerTCP.SOA = dnsServerUDP.SOA
		go dnsServerUDP.Start(errChan)
		go dnsServerTCP.Start(errChan)
	} else {
		dnsServer := NewDNSServer(db, config.DNS.Listen, config.DNS.Proto, config.DNS.Domain)
		dnsservers = append(dnsservers, dnsServer)
		dnsServer.ParseRecords(&config)
		go dnsServer.Start(errChan)
	}

	// HTTP API
	go startHTTPAPI(errChan, &config, db, dnsservers)

	// block waiting for error
	for {
		if err := <-errChan; err != nil {
			log.Fatal(err)
		}
	}
}

func startHTTPAPI(errChan chan error, config *Config, db database, dnsservers []*DNSServer) {
	// Setup http logger
	logger := log.New()
	logwriter := logger.Writer()
	defer logwriter.Close()
	// Setup logging for different dependencies to log with logrus
	// Certmagic
	stdlog.SetOutput(logwriter)

	api := http.NewServeMux()
	if !config.API.DisableRegistration {
		api.Handle("/register", webRegisterHandler{config, db})
	}
	api.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		authMiddleware{config, db}.ServeHTTP(w, r, webUpdateHandler{db}.ServeHTTP)
	})
	api.HandleFunc("/health", healthCheck)

	// TLS specific general settings
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	var err error
	if config.API.TLS {
		srv := &http.Server{
			Addr:      config.API.Listen,
			Handler:   api,
			TLSConfig: cfg,
			ErrorLog:  stdlog.New(logwriter, "", 0),
		}
		log.WithFields(log.Fields{"host": config.API.Listen}).Info("Listening HTTPS")
		err = srv.ListenAndServeTLS(config.API.TLSCertFullchain, config.API.TLSCertPrivkey)
	} else {
		log.WithFields(log.Fields{"host": config.API.Listen}).Info("Listening HTTP")
		err = http.ListenAndServe(config.API.Listen, api)
	}
	if err != nil {
		errChan <- err
	}
}
