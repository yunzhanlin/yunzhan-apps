package executor

import "local/panel/internal/core"

// Only a fixed, public challenge endpoint is proxied. No browser cookie or body is forwarded.
func siteACMEConfig(site core.Site) string {
	if !site.Settings.ACME {
		return ""
	}
	return "  location ^~ /.well-known/acme-challenge/ {\n    limit_except GET { deny all; }\n    proxy_pass http://127.0.0.1:19100;\n    proxy_set_header Host $host;\n    proxy_set_header Cookie \"\";\n    proxy_set_header Authorization \"\";\n    proxy_pass_request_body off;\n    proxy_set_header Content-Length \"\";\n    proxy_connect_timeout 2s;\n    proxy_read_timeout 5s;\n    access_log off;\n  }\n"
}
