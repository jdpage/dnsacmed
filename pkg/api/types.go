package api

// API config
type Config struct {
	Listen              string `json:"listen"`
	DisableRegistration bool   `json:"disable_registration"`
	TLS                 bool   `json:"tls"`
	TLSCertPrivkey      string `json:"tls_cert_privkey"`
	TLSCertFullchain    string `json:"tls_cert_fullchain"`
	UseHeader           bool   `json:"use_header"`
	HeaderName          string `json:"header_name"`
}
