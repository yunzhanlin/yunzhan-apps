//go:build !linux

package executor

import (
	"errors"
	"net/http"
)

func (s *Service) redisRoutes(m *http.ServeMux) {}
func ServeRedis(id string) error                { return errors.New("Redis 实例仅支持 Linux") }
