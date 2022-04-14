package model

import (
	"testing"
)

func TestGetValidCIDRMasks(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  CIDRSlice
		output CIDRSlice
	}{
		{"all ok", CIDRSlice{"10.0.0.1/24"}, CIDRSlice{"10.0.0.1/24"}},
		{"invalid", CIDRSlice{"invalid", "127.0.0.1/32"}, CIDRSlice{"127.0.0.1/32"}},
		{"ipv6", CIDRSlice{"2002:c0a8::0/32", "8.8.8.8/32"}, CIDRSlice{"2002:c0a8::0/32", "8.8.8.8/32"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ret := test.input.ValidEntries()
			if len(ret) == len(test.output) {
				for i, v := range ret {
					if v != test.output[i] {
						t.Errorf("Expected %q but got %q", test.output, ret)
					}
				}
			} else {
				t.Errorf("Expected %q but got %q", test.output, ret)
			}
		})
	}
}
