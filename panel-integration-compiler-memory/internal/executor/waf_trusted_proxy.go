package executor

import (
	"fmt"
	"local/panel/internal/core"
	"strings"
)

func renderWAFTrustedProxy(cfg *core.WAFTrustedProxyConfig) string {
	if cfg == nil || !cfg.Enabled {
		return ""
	}
	var out strings.Builder
	out.WriteString("# explicit trusted proxy peers; unlisted peers cannot supply client identity\n")
	for _, peer := range cfg.TrustedCIDRs {
		fmt.Fprintf(&out, "set_real_ip_from %s;\n", peer)
	}
	fmt.Fprintf(&out, "real_ip_header %s;\n", cfg.Header)
	recursive := "off"
	if cfg.Recursive {
		recursive = "on"
	}
	fmt.Fprintf(&out, "real_ip_recursive %s;\n", recursive)
	return out.String()
}
