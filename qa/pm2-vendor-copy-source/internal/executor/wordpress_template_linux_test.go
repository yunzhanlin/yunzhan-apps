//go:build linux

package executor

import (
	"encoding/json"
	"testing"
)

func TestWordPressTemplatePortRequiresPrivateExactServices(t *testing.T) {
	decode := func(source string) composeConfig {
		var config composeConfig
		if e := json.Unmarshal([]byte(source), &config); e != nil {
			t.Fatal(e)
		}
		return config
	}
	good := `{"services":{"wordpress":{"image":"wordpress:7.1.2-php8.3-apache","ports":[{"host_ip":"127.0.0.1","target":80,"published":"18480","protocol":"tcp"}]},"db":{"image":"mariadb:11.8.9"}}}`
	port, e := wordPressTemplatePort(decode(good))
	if e != nil || port != 18480 {
		t.Fatal("private WordPress template rejected", e)
	}
	bad := []string{
		`{"services":{"wordpress":{"image":"wordpress:latest","ports":[{"host_ip":"127.0.0.1","target":80,"published":"18480","protocol":"tcp"}]},"db":{"image":"mariadb:11.8.9"}}}`,
		`{"services":{"wordpress":{"image":"wordpress:7.1.2-php8.3-apache","ports":[{"host_ip":"0.0.0.0","target":80,"published":"18480","protocol":"tcp"}]},"db":{"image":"mariadb:11.8.9"}}}`,
		`{"services":{"wordpress":{"image":"wordpress:7.1.2-php8.3-apache","ports":[{"host_ip":"127.0.0.1","target":80,"published":"18480","protocol":"tcp"}]},"db":{"image":"mariadb:11.8.9","ports":[{"host_ip":"127.0.0.1","target":3306,"published":"18306","protocol":"tcp"}]}}}`,
	}
	for _, source := range bad {
		if _, e := wordPressTemplatePort(decode(source)); e == nil {
			t.Fatal("unsafe WordPress template accepted")
		}
	}
}

func TestTemplatePublishedPortRequiresExactlyOnePrivatePort(t *testing.T) {
	decode := func(source string) composeConfig {
		var config composeConfig
		if e := json.Unmarshal([]byte(source), &config); e != nil {
			t.Fatal(e)
		}
		return config
	}
	good := `{"services":{"memcached":{"image":"memcached:1.6.45-alpine","ports":[{"host_ip":"127.0.0.1","target":11211,"published":"21211","protocol":"tcp"}]}}}`
	port, e := templatePublishedPort(decode(good))
	if e != nil || port != 21211 {
		t.Fatal("private application template port rejected", e)
	}
	bad := []string{
		`{"services":{"memcached":{"image":"memcached:1.6.45-alpine"}}}`,
		`{"services":{"memcached":{"image":"memcached:1.6.45-alpine","ports":[{"host_ip":"0.0.0.0","target":11211,"published":"21211","protocol":"tcp"}]}}}`,
		`{"services":{"memcached":{"image":"memcached:1.6.45-alpine","ports":[{"host_ip":"127.0.0.1","target":11211,"published":"21211","protocol":"tcp"},{"host_ip":"127.0.0.1","target":11212,"published":"21212","protocol":"tcp"}]}}}`,
	}
	for _, source := range bad {
		if _, e := templatePublishedPort(decode(source)); e == nil {
			t.Fatal("unsafe application template port accepted")
		}
	}
}
