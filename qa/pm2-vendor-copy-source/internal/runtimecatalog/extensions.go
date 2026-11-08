package runtimecatalog

import "path/filepath"

type Extension struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"source_url"`
	SHA256  string `json:"sha256"`
}

var Extensions = []Extension{{ID: "redis-6.3.0", Name: "redis", Version: "6.3.0", URL: "https://pecl.php.net/get/redis-6.3.0.tgz", SHA256: "0d5141f634bd1db6c1ddcda053d25ecf2c4fc1c395430d534fd3f8d51dd7f0b5"}}

func FindExtension(id string) (Extension, bool) {
	for _, e := range Extensions {
		if e.ID == id {
			return e, true
		}
	}
	return Extension{}, false
}
func (e Extension) Prefix(php Release) string {
	return filepath.Join("/opt/panel/php-extensions", php.ID, e.Name, e.Version)
}
