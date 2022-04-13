package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// Records is a slice of ResourceRecords
type Records struct {
	Records []dns.RR
}

// DNSServer is the main struct for acme-dns DNS server
type DNSServer struct {
	logger          *zap.Logger
	DB              database
	Domain          string
	Server          *dns.Server
	SOA             dns.RR
	PersonalKeyAuth string
	Domains         map[string]Records
}

// NewDNSServer parses the DNS records from config and returns a new DNSServer struct
func NewDNSServer(logger *zap.Logger, db database, addr string, proto string, domain string) *DNSServer {
	var server DNSServer
	server.logger = logger
	server.Server = &dns.Server{Addr: addr, Net: proto}
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	server.Domain = strings.ToLower(domain)
	server.DB = db
	server.PersonalKeyAuth = ""
	server.Domains = make(map[string]Records)
	return &server
}

// Start starts the DNSServer
func (d *DNSServer) Start(errorChannel chan error) {
	// DNS server part
	dns.HandleFunc(".", d.handleRequest)
	d.logger.Info("Listening DNS", zap.String("addr", d.Server.Addr), zap.String("proto", d.Server.Net))
	err := d.Server.ListenAndServe()
	if err != nil {
		errorChannel <- err
	}
}

// ParseRecords parses a slice of DNS record string
func (d *DNSServer) ParseRecords(config *Config) {
	for _, v := range config.DNS.StaticRecords {
		rr, err := dns.NewRR(strings.ToLower(v))
		if err != nil {
			d.logger.Warn("Could not parse RR from config", zap.Error(err), zap.String("rr", v))
			continue
		}
		// Add parsed RR
		d.appendRR(rr)
	}
	// Create serial
	serial := time.Now().Format("2006010215")
	// Add SOA
	SOAstring := fmt.Sprintf("%s. SOA %s. %s. %s 28800 7200 604800 86400", strings.ToLower(config.DNS.Domain), strings.ToLower(config.DNS.NSName), strings.ToLower(config.DNS.NSAdmin), serial)
	soarr, err := dns.NewRR(SOAstring)
	if err != nil {
		d.logger.Error("While adding SOA record", zap.Error(err), zap.String("soa", SOAstring))
	} else {
		d.appendRR(soarr)
		d.SOA = soarr
	}
}

func (d *DNSServer) appendRR(rr dns.RR) {
	addDomain := rr.Header().Name
	_, ok := d.Domains[addDomain]
	if !ok {
		d.Domains[addDomain] = Records{[]dns.RR{rr}}
	} else {
		drecs := d.Domains[addDomain]
		drecs.Records = append(drecs.Records, rr)
		d.Domains[addDomain] = drecs
	}
	d.logger.Debug("Adding new record to domain", zap.String("recordtype", dns.TypeToString[rr.Header().Rrtype]), zap.String("domain", addDomain))
}

func (d *DNSServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	// handle edns0
	opt := r.IsEdns0()
	if opt != nil {
		if opt.Version() != 0 {
			// Only EDNS0 is standardized
			m.MsgHdr.Rcode = dns.RcodeBadVers
			m.SetEdns0(512, false)
		} else {
			// We can safely do this as we know that we're not setting other OPT RRs within acme-dns.
			m.SetEdns0(512, false)
			if r.Opcode == dns.OpcodeQuery {
				d.readQuery(m)
			}
		}
	} else {
		if r.Opcode == dns.OpcodeQuery {
			d.readQuery(m)
		}
	}
	_ = w.WriteMsg(m)
}

func (d *DNSServer) readQuery(m *dns.Msg) {
	var authoritative = false
	for _, que := range m.Question {
		if rr, rc, auth, err := d.answer(que); err == nil {
			if auth {
				authoritative = auth
			}
			m.MsgHdr.Rcode = rc
			m.Answer = append(m.Answer, rr...)
		}
	}
	m.MsgHdr.Authoritative = authoritative
	if authoritative {
		if m.MsgHdr.Rcode == dns.RcodeNameError {
			m.Ns = append(m.Ns, d.SOA)
		}
	}
}

func (d *DNSServer) getRecord(q dns.Question) ([]dns.RR, error) {
	var rr []dns.RR
	var cnames []dns.RR
	domain, ok := d.Domains[strings.ToLower(q.Name)]
	if !ok {
		return rr, fmt.Errorf("No records for domain %s", q.Name)
	}
	for _, ri := range domain.Records {
		if ri.Header().Rrtype == q.Qtype {
			rr = append(rr, ri)
		}
		if ri.Header().Rrtype == dns.TypeCNAME {
			cnames = append(cnames, ri)
		}
	}
	if len(rr) == 0 {
		return cnames, nil
	}
	return rr, nil
}

// answeringForDomain checks if we have any records for a domain
func (d *DNSServer) answeringForDomain(name string) bool {
	if d.Domain == strings.ToLower(name) {
		return true
	}
	_, ok := d.Domains[strings.ToLower(name)]
	return ok
}

func (d *DNSServer) isAuthoritative(q dns.Question) bool {
	if d.answeringForDomain(q.Name) {
		return true
	}
	domainParts := strings.Split(strings.ToLower(q.Name), ".")
	for i := range domainParts {
		if d.answeringForDomain(strings.Join(domainParts[i:], ".")) {
			return true
		}
	}
	return false
}

// isOwnChallenge checks if the query is for the domain of this acme-dns instance. Used for answering its own ACME challenges
func (d *DNSServer) isOwnChallenge(name string) bool {
	domainParts := strings.SplitN(name, ".", 2)
	if len(domainParts) == 2 {
		if strings.ToLower(domainParts[0]) == "_acme-challenge" {
			domain := strings.ToLower(domainParts[1])
			if !strings.HasSuffix(domain, ".") {
				domain = domain + "."
			}
			if domain == d.Domain {
				return true
			}
		}
	}
	return false
}

func (d *DNSServer) answer(q dns.Question) ([]dns.RR, int, bool, error) {
	var rcode int
	var err error
	var txtRRs []dns.RR
	var authoritative = d.isAuthoritative(q)
	if !d.isOwnChallenge(q.Name) && !d.answeringForDomain(q.Name) {
		rcode = dns.RcodeNameError
	}
	r, _ := d.getRecord(q)
	if q.Qtype == dns.TypeTXT {
		if d.isOwnChallenge(q.Name) {
			txtRRs, err = d.answerOwnChallenge(q)
		} else {
			txtRRs, err = d.answerTXT(q)
		}
		if err == nil {
			r = append(r, txtRRs...)
		}
	}
	if len(r) > 0 {
		// Make sure that we return NOERROR if there were dynamic records for the domain
		rcode = dns.RcodeSuccess
	}
	d.logger.Debug("Answering question for domain", zap.String("qtype", dns.TypeToString[q.Qtype]), zap.String("domain", q.Name), zap.String("rcode", dns.RcodeToString[rcode]))
	return r, rcode, authoritative, nil
}

func (d *DNSServer) answerTXT(q dns.Question) ([]dns.RR, error) {
	var ra []dns.RR
	subdomain := sanitizeDomainQuestion(q.Name)
	atxt, err := d.DB.GetTXTForDomain(subdomain)
	if err != nil {
		d.logger.Error("While trying to get record", zap.Error(err))
		return ra, err
	}
	for _, v := range atxt {
		if len(v) > 0 {
			r := new(dns.TXT)
			r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}
			r.Txt = append(r.Txt, v)
			ra = append(ra, r)
		}
	}
	return ra, nil
}

// answerOwnChallenge answers to ACME challenge for acme-dns own certificate
func (d *DNSServer) answerOwnChallenge(q dns.Question) ([]dns.RR, error) {
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}
	r.Txt = append(r.Txt, d.PersonalKeyAuth)
	return []dns.RR{r}, nil
}
