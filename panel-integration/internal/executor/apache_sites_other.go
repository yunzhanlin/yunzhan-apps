//go:build !linux

package executor

import (
	"context"
	"local/panel/internal/core"
)

func (s *Service) applyApacheSites(_ context.Context, _ []core.Site, _ func(string)) (func() error, error) {
	return func() error { return nil }, nil
}
