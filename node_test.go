package main

import "testing"

func TestXray_addRulesRouting_AND_delRulesRouting_(t *testing.T) {
	rs := []string{"domain:a.com", "domain:b.com"}
	err := x.addRulesRouting(rs)
	if err != nil {
		t.Fatal(err)
	}
	err = x.delRulesRouting(rs)
	if err != nil {
		t.Fatal(err)
	}
}
