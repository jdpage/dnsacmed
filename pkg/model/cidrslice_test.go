package model

import (
	"testing"
)

func TestGetValidCIDRMasks(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  []string
		output []string
	}{
		{"all ok", []string{"10.0.0.1/24"}, []string{"10.0.0.0/24"}},
		{"invalid", []string{"invalid", "127.0.0.1/32"}, []string{"127.0.0.1/32"}},
		{"ipv6", []string{"2002:c0a8::0/32", "8.8.8.8/32"}, []string{"2002:c0a8::/32", "8.8.8.8/32"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nets, _ := ParseCIDRSlice(test.input)
			if len(nets) == len(test.output) {
				for i, n := range nets {
					if n.String() != test.output[i] {
						t.Errorf("Expected %v but got %v", test.output, nets)
					}
				}
			} else {
				t.Errorf("Expected %v but got %v", test.output, nets)
			}
		})
	}
}
