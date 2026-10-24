package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

func checkACMEHTTP01(ctx context.Context, domain, token, expected string) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/.well-known/acme-challenge/"+token, nil)
	if e != nil {
		return e
	}
	req.Host = domain
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 1024))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 || string(body) != expected {
		return errors.New("实际 Nginx HTTP-01 验证入口未返回本次令牌")
	}
	return nil
}
