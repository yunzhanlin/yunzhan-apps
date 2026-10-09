//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Service) probeAnalyticsHTMLLoaded(ctx context.Context, identity analyticsHTMLEngineIdentity) error {
	socket := s.systemPath(analyticsHTMLHealthSocket)
	if err := s.wafOwnedDirectory(filepath.Dir(socket), false); err != nil {
		return err
	}
	st, err := os.Lstat(socket)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return errors.New("HTML 引擎实际工作进程检查套接字缺失或类型异常")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("HTML 引擎工作进程套接字所有者或链接异常")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://analytics-engine.invalid/health", nil)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("HTML 引擎实际工作进程无法应答")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Set-Cookie")) != 0 {
		return errors.New("HTML 引擎工作进程响应契约不符")
	}
	var out struct {
		Protocol   string `json:"protocol"`
		JobID      string `json:"job_id"`
		ProgramSHA string `json:"program_sha256"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 {
		return errors.New("HTML 引擎工作进程响应读取失败或超过限额")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(&struct{}{}) != io.EOF || out.Protocol != "yunzhan-analytics-html-v1" || out.JobID != identity.JobID || out.ProgramSHA != identity.ProgramSHA {
		return errors.New("HTML 引擎工作进程仍为旧版本或身份不匹配")
	}
	return nil
}

func (s *Service) waitAnalyticsHTMLLoaded(ctx context.Context, identity analyticsHTMLEngineIdentity) error {
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		err = s.probeAnalyticsHTMLLoaded(ctx, identity)
		if err == nil {
			return nil
		}
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (s *Service) analyticsHTMLListenerAbsent(ctx context.Context) (bool, error) {
	socket := s.systemPath(analyticsHTMLHealthSocket)
	if err := s.wafOwnedDirectory(filepath.Dir(socket), false); err != nil {
		return false, err
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	if err == nil {
		connection.Close()
		return false, nil
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return true, nil
	}
	return false, errors.New("HTML 监听不存在无法核实；权限或超时不等同于已卸载")
}
