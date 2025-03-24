package main

import "testing"

func TestXray_addRulesRouting(t *testing.T) {
	err := x.addRulesRouting([]string{"domain:a.com"})
	if err != nil {
		t.Fatal(err)
	}
}
