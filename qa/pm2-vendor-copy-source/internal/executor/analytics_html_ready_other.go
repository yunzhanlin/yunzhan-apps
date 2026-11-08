//go:build !linux

package executor

import (
	"context"
	"errors"
)

func (s *Service) requireAnalyticsHTMLReady(context.Context) error {
	return errors.New("独立 HTML 自动接入引擎仅支持经过原生验收的 Linux Nginx")
}
