package api

import (
	"net/http"
	"testing"

	"github.com/jdpage/dnsacmed/pkg/model"
	"go.uber.org/zap/zaptest"
)

func TestGetIPListFromHeader(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  string
		output []string
	}{
		{"typical", "1.1.1.1, 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{"odd spacing", " 1.1.1.1 , 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{"empty elements", ",1.1.1.1 ,2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			res := getIPListFromHeader(test.input)
			if len(res) != len(test.output) {
				t.Errorf("Expected [%d] items in return list, but got [%d]", len(test.output), len(res))
			} else {
				for j, vv := range test.output {
					if res[j] != vv {
						t.Errorf("Expected return value [%v] but got [%v]", test.output, res)
					}
				}
			}
		})
	}
}

func TestUpdateAllowedFromIP(t *testing.T) {
	m := authMiddleware{
		config: &Config{UseHeader: false},
		logger: zaptest.NewLogger(t),
	}
	userWithAllow, err := model.NewACMETxt()
	if err != nil {
		panic(err)
	}
	userWithAllow.AllowFrom = model.CIDRSlice{"192.168.1.2/32", "[::1]/128"}
	userWithoutAllow, err := model.NewACMETxt()
	if err != nil {
		panic(err)
	}

	for i, test := range []struct {
		remoteaddr string
		expected   bool
	}{
		{"192.168.1.2:1234", true},
		{"192.168.1.1:1234", false},
		{"invalid", false},
		{"[::1]:4567", true},
	} {
		newreq, _ := http.NewRequest("GET", "/whatever", nil)
		newreq.RemoteAddr = test.remoteaddr
		ret := m.updateAllowedFromIP(newreq, userWithAllow)
		if test.expected != ret {
			t.Errorf("Test %d: Unexpected result for user with allowForm set", i)
		}

		if !m.updateAllowedFromIP(newreq, userWithoutAllow) {
			t.Errorf("Test %d: Unexpected result for user without allowForm set", i)
		}
	}
}
