//go:build !test
// +build !test

package main

import (
	"crypto/tls"
	"flag"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func main() {
	// Created files are not world writable
	syscall.Umask(0077)
	configPtr := flag.String("c", "/etc/dnsacmed/config.cfg", "config file location")
	flag.Parse()
	// Read global config
	var config DNSConfig
	var err error
	if fileIsAccessible(*configPtr) {
		log.WithFields(log.Fields{"file": *configPtr}).Info("Using config file")
		config, err = readConfig(*configPtr)
	} else if fileIsAccessible("./config.cfg") {
		log.WithFields(log.Fields{"file": "./config.cfg"}).Info("Using config file")
		config, err = readConfig("./config.cfg")
	} else {
		log.Errorf("Configuration file not found.")
		os.Exit(1)
	}
	if err != nil {
		log.Errorf("Encountered an error while trying to read configuration file:  %s", err)
		os.Exit(1)
	}

	setupLogging(config.Logconfig.Format, config.Logconfig.Level)

	// Open database
	db := new(acmedb)
	err = db.Init(config.Database.Engine, config.Database.Connection)
	if err != nil {
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
	if strings.HasPrefix(config.General.Proto, "both") {
		// Handle the case where DNS server should be started for both udp and tcp
		udpProto := "udp"
		tcpProto := "tcp"
		if strings.HasSuffix(config.General.Proto, "4") {
			udpProto += "4"
			tcpProto += "4"
		} else if strings.HasSuffix(config.General.Proto, "6") {
			udpProto += "6"
			tcpProto += "6"
		}
		dnsServerUDP := NewDNSServer(db, config.General.Listen, udpProto, config.General.Domain)
		dnsservers = append(dnsservers, dnsServerUDP)
		dnsServerUDP.ParseRecords(config)
		dnsServerTCP := NewDNSServer(db, config.General.Listen, tcpProto, config.General.Domain)
		dnsservers = append(dnsservers, dnsServerTCP)
		// No need to parse records from config again
		dnsServerTCP.Domains = dnsServerUDP.Domains
		dnsServerTCP.SOA = dnsServerUDP.SOA
		go dnsServerUDP.Start(errChan)
		go dnsServerTCP.Start(errChan)
	} else {
		dnsServer := NewDNSServer(db, config.General.Listen, config.General.Proto, config.General.Domain)
		dnsservers = append(dnsservers, dnsServer)
		dnsServer.ParseRecords(config)
		go dnsServer.Start(errChan)
	}

	// HTTP API
	go startHTTPAPI(errChan, &config, db, dnsservers)

	// block waiting for error
	for {
		err = <-errChan
		if err != nil {
			log.Fatal(err)
		}
	}
}

func startHTTPAPI(errChan chan error, config *DNSConfig, db database, dnsservers []*DNSServer) {
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

	host := config.API.IP + ":" + config.API.Port

	// TLS specific general settings
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	var err error
	switch config.API.TLS {
	case "cert":
		srv := &http.Server{
			Addr:      host,
			Handler:   api,
			TLSConfig: cfg,
			ErrorLog:  stdlog.New(logwriter, "", 0),
		}
		log.WithFields(log.Fields{"host": host}).Info("Listening HTTPS")
		err = srv.ListenAndServeTLS(config.API.TLSCertFullchain, config.API.TLSCertPrivkey)
	default:
		log.WithFields(log.Fields{"host": host}).Info("Listening HTTP")
		err = http.ListenAndServe(host, api)
	}
	if err != nil {
		errChan <- err
	}
}
