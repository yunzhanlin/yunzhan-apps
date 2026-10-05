package core

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginEventsBoundedAndRemoteAddress(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "panel.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::ffff:192.0.2.8]:4567"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if ip := clientRemoteIP(r); ip != "192.0.2.8" {
		t.Fatalf("trusted forwarded IP: %s", ip)
	}
	if e = s.RecordLoginEvent("admin", clientRemoteIP(r), "denied"); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordLoginEvent("admin", "not-an-ip", "success"); e != nil {
		t.Fatal(e)
	}
	items, e := s.LoginEvents(100)
	if e != nil {
		t.Fatal(e)
	}
	if len(items) != 2 || items[0].IP != "unknown" || items[1].IP != "192.0.2.8" {
		t.Fatalf("events: %+v", items)
	}
}

func TestPublicHTTPClientAddressAndRateLimit(t *testing.T) {
	a := &Server{attempts: map[string][]time.Time{}}
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "127.0.0.1:43210"
	r.Header.Set("X-Real-IP", "192.0.2.8")
	if got := clientRemoteIP(r); got != "127.0.0.1" {
		t.Fatalf("unmarked proxy address was trusted: %s", got)
	}
	r.Header.Set("X-Panel-Connection", "public-http")
	for i := 0; i < 8; i++ {
		if !a.allowedScope(r, "login") {
			t.Fatal("visitor rejected before limit")
		}
	}
	if a.allowedScope(r, "login") || clientRemoteIP(r) != "192.0.2.8" {
		t.Fatal("visitor limit or source address incorrect")
	}
	r.Header.Set("X-Real-IP", "192.0.2.9")
	if !a.allowedScope(r, "login") {
		t.Fatal("different visitor inherited first visitor's limit")
	}
}
