//go:build !linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
)

func (s *Service) preparePHP(ctx context.Context, site core.Site, dir string, add func(string)) (func(bool) error, string, error) {
	if site.PHPVersionID != "" {
		return nil, "", errors.New("requires Linux")
	}
	return func(bool) error { return nil }, "", nil
}
func phpConfig(site core.Site, dir string) string {
	return "  location ~* \\.(php|phtml|phar)(/|$) { return 404; }\n"
}
func phpVersion(id string) string { return "" }

func phpProbeConfig(site core.Site) string { return "" }

func (s *Service) phpSettingsPreview(site core.Site) (string, string, error) { return "", "", nil }
