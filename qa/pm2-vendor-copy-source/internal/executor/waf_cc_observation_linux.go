//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
)

// The wildcard server include must not hide an administrator's additional
// limiter. Observation refuses unknown files rather than weakening them.
func (s *Service) verifyWAFCCObservationIncludes() error {
	_, server := wafFiles(s)
	dir := filepath.Dir(server)
	if err := s.wafOwnedDirectory(dir, false); errors.Is(err, os.ErrNotExist) {
		return nil // Fresh installation will create only its own exact include.
	} else if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(server) || entry.IsDir() {
			return errors.New("WAF server 包含额外配置，观察模式不能证明其它限速仍阻断，未修改")
		}
	}
	return nil
}
