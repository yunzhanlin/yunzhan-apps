package core

import (
	"strings"
	"testing"
)

func TestLoadBalanceHTTPHealthClosedPolicy(t *testing.T) {
	valid := LoadBalanceHTTPHealth{Path: "/ready?check=1", Interval: 30, TimeoutMS: 500, ExpectedStatus: 200, BodyContains: "READY", Failures: 2, Successes: 2}
	if ValidateLoadBalanceHTTPHealth(nil) != nil || ValidateLoadBalanceHTTPHealth(&valid) != nil {
		t.Fatal("valid policy rejected")
	}
	cases := map[string]func(*LoadBalanceHTTPHealth){
		"absolute":           func(v *LoadBalanceHTTPHealth) { v.Path = "http://169.254.169.254/latest/meta-data" },
		"relative authority": func(v *LoadBalanceHTTPHealth) { v.Path = "//example.com/ready" },
		"blank":              func(v *LoadBalanceHTTPHealth) { v.Path = "" },
		"fragment":           func(v *LoadBalanceHTTPHealth) { v.Path = "/ready#x" },
		"space":              func(v *LoadBalanceHTTPHealth) { v.Path = "/ready x" },
		"backslash":          func(v *LoadBalanceHTTPHealth) { v.Path = "/ready\\x" },
		"newline":            func(v *LoadBalanceHTTPHealth) { v.Path = "/ready%0D%0AHost:bad" },
		"tab":                func(v *LoadBalanceHTTPHealth) { v.Path = "/ready%09x" },
		"nul":                func(v *LoadBalanceHTTPHealth) { v.Path = "/ready%00x" },
		"bad escape":         func(v *LoadBalanceHTTPHealth) { v.Path = "/ready%XX" },
		"unicode":            func(v *LoadBalanceHTTPHealth) { v.Path = "/就绪" },
		"large path":         func(v *LoadBalanceHTTPHealth) { v.Path = "/" + strings.Repeat("a", 512) },
		"interval low":       func(v *LoadBalanceHTTPHealth) { v.Interval = 29 },
		"interval high":      func(v *LoadBalanceHTTPHealth) { v.Interval = 3601 },
		"timeout low":        func(v *LoadBalanceHTTPHealth) { v.TimeoutMS = 499 },
		"timeout high":       func(v *LoadBalanceHTTPHealth) { v.TimeoutMS = 5001 },
		"redirect":           func(v *LoadBalanceHTTPHealth) { v.ExpectedStatus = 302 },
		"server error":       func(v *LoadBalanceHTTPHealth) { v.ExpectedStatus = 503 },
		"zero fail":          func(v *LoadBalanceHTTPHealth) { v.Failures = 0 },
		"large fail":         func(v *LoadBalanceHTTPHealth) { v.Failures = 11 },
		"zero rise":          func(v *LoadBalanceHTTPHealth) { v.Successes = 0 },
		"large rise":         func(v *LoadBalanceHTTPHealth) { v.Successes = 11 },
		"large match":        func(v *LoadBalanceHTTPHealth) { v.BodyContains = strings.Repeat("a", 257) },
		"nul match":          func(v *LoadBalanceHTTPHealth) { v.BodyContains = "a\x00b" },
		"invalid utf8":       func(v *LoadBalanceHTTPHealth) { v.BodyContains = string([]byte{255}) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			v := valid
			edit(&v)
			if ValidateLoadBalanceHTTPHealth(&v) == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
