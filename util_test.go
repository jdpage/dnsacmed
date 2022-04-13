package main

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestSetupLogging(t *testing.T) {
	for i, test := range []struct {
		format   string
		level    string
		expected string
	}{
		{"text", "warning", "warning"},
		{"json", "debug", "debug"},
		{"text", "info", "info"},
		{"json", "error", "error"},
		{"text", "something", "warning"},
	} {
		setupLogging(test.format, test.level)
		if log.GetLevel().String() != test.expected {
			t.Errorf("Test %d: Expected loglevel %s but got %s", i, test.expected, log.GetLevel().String())
		}
	}
}

func TestGetIPListFromHeader(t *testing.T) {
	for i, test := range []struct {
		input  string
		output []string
	}{
		{"1.1.1.1, 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{" 1.1.1.1 , 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{",1.1.1.1 ,2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
	} {
		res := getIPListFromHeader(test.input)
		if len(res) != len(test.output) {
			t.Errorf("Test %d: Expected [%d] items in return list, but got [%d]", i, len(test.output), len(res))
		} else {

			for j, vv := range test.output {
				if res[j] != vv {
					t.Errorf("Test %d: Expected return value [%v] but got [%v]", j, test.output, res)
				}

			}
		}
	}
}
