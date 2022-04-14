package dns

// Config file DNS section
type Config struct {
	Listen        string   `json:"listen"`
	Proto         string   `json:"protocol"`
	Domain        string   `json:"domain"`
	NSName        string   `json:"nsname"`
	NSAdmin       string   `json:"nsadmin"`
	StaticRecords []string `json:"records"`
}
