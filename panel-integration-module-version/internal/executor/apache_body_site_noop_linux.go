//go:build linux

package executor

import (
	"local/panel/internal/core"
)

// Render only. A byte-identical website plan is not authority to load a DSO,
// create native cache directories or claim a running protected Apache. Actual
// changes still take the original sealed-engine and live-generation path.
func apacheBodySitePolicy(content string, cfg core.WAFConfig, module string) (string, string, error) {
	if _, err := core.DecodeApacheWAFNativeBodyConfig(core.WAFSettings(cfg)); err != nil {
		return "", "", err
	}
	prepared, err := prepareApacheWAFTrustedProxySource(content, cfg.TrustedProxy, module)
	if err != nil {
		return "", "", err
	}
	prepared, err = transitionApacheBodySource(prepared, core.DefaultApacheWAFConfig(), cfg)
	if err != nil {
		return "", "", err
	}
	bindings, err := apacheWAFBindings(prepared)
	if err != nil {
		return "", "", err
	}
	rules, err := renderApacheWAFVersion(cfg, bindings, core.ApacheWAFNativeBodyVersion)
	return prepared, rules, err
}

// Validate every native block before removing it from the comparison view.
// Only the already reviewed single global remoteip LoadModule relocation may
// differ. No other directive, body policy, engine identity or host may change.
func apacheBodySiteSourceSame(candidate, original string, cfg core.WAFConfig, module string) (bool, error) {
	bare := make([]string, 0, 2)
	for _, source := range []string{candidate, original} {
		checked, err := transitionApacheBodySource(source, cfg, cfg)
		if err != nil {
			return false, err
		}
		if checked != source {
			return false, nil
		}
		outside, err := transitionApacheBodySource(source, cfg, core.DefaultApacheWAFConfig())
		if err != nil {
			return false, err
		}
		bare = append(bare, outside)
	}
	return apacheMetadataSiteSourceSame(bare[0], bare[1], cfg, module), nil
}
