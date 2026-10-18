//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Service) statisticsHealthSocket() string {
	return s.systemPath("/run/panel-nginx/statistics-log-health.sock")
}
func (s *Service) statisticsHealthSocketInfo() error {
	path := s.statisticsHealthSocket()
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("统计探针套接字类型、所有者或链接数异常")
	}
	return nil
}
func (s *Service) statisticsHealthLoaded(ctx context.Context, nonce string) error {
	if !statisticsHealthNonceOnlyPattern.MatchString(nonce) {
		return errors.New("统计探针期望身份异常")
	}
	if err := s.statisticsHealthSocketInfo(); err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "unix", s.statisticsHealthSocket())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", "http://panel-statistics-log-health/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("统计生效探针尚未可读")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 129))
	if err != nil || response.StatusCode != 200 || string(body) != "yunzhan-statistics-log-v2:"+nonce {
		return errors.New("统计探针返回的已加载身份不匹配")
	}
	return nil
}
func (s *Service) statisticsHealthAbsent(ctx context.Context) error {
	path := s.statisticsHealthSocket()
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return err
	}
	if err := s.statisticsHealthSocketInfo(); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "unix", path)
	if err == nil {
		conn.Close()
		return errors.New("原配置没有统计探针，但旧监听仍在运行")
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("统计探针监听状态无法核对")
}
func (s *Service) waitStatisticsHealth(ctx context.Context, source []byte) error {
	nonce, err := statisticsHealthConfigNonce(source, s.statisticsHealthSocket())
	if err != nil {
		return err
	}
	var last error
	for i := 0; i < 30; i++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		if nonce == "" {
			last = s.statisticsHealthAbsent(ctx)
		} else {
			last = s.statisticsHealthLoaded(ctx, nonce)
		}
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return last
}
