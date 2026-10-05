package executor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func renderSiteTLS(site core.Site, root, plain string) string {
	if site.Settings.TLS == nil {
		return plain
	}
	options := site.Settings.TLS
	certDir := filepath.Join(certificateRoot, options.CertificateID)
	directives := fmt.Sprintf("  listen 127.0.0.1:19102 ssl;\n  ssl_certificate %s;\n  ssl_certificate_key %s;\n  ssl_protocols TLSv1.2 TLSv1.3;\n  ssl_session_cache shared:panel_tls:10m;\n", strconv.Quote(filepath.Join(certDir, "chain.pem")), strconv.Quote(filepath.Join(certDir, "key.pem")))
	if !options.Redirect {
		return strings.Replace(plain, "  listen 127.0.0.1:19101;\n", "  listen 127.0.0.1:19101;\n"+directives, 1)
	}
	secure := strings.Replace(plain, "  listen 127.0.0.1:19101;\n", directives, 1)
	redirect := fmt.Sprintf("server {\n%s  listen 127.0.0.1:19101;\n  server_name %s;\n  add_header X-Panel-Config %s always;\n  location = %s { default_type text/plain; access_log off; return 200 %s; }\n  location / { return 301 https://$host:19102$request_uri; }\n}\n", siteWAFInclude(site), strings.Join(append([]string{site.Domain}, site.Settings.Domains...), " "), strconv.Quote(core.Hash(siteHealthBody(site))), siteHealthPath(site), strconv.Quote(siteHealthBody(site)))
	redirect = strings.Replace(redirect, "  location / { return 301", siteACMEConfig(site)+"  location / { return 301", 1)
	return secure + redirect
}
func siteURL(site core.Site, path string) string {
	if site.Settings.TLS != nil {
		return "https://127.0.0.1:19102" + path
	}
	return "http://127.0.0.1:19101" + path
}
func siteHTTPSClient(site core.Site, domain string) (*http.Client, error) {
	cert, e := LoadCertificate(site.Settings.TLS.CertificateID)
	if e != nil {
		return nil, e
	}
	if e = cert.ValidateDomains(site.Domain, site.Settings.Domains, time.Now()); e != nil {
		return nil, e
	}
	block, _ := pem.Decode([]byte(cert.PEM))
	if block == nil {
		return nil, errors.New("实际证书无法读取")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, e
	}
	// Trust exactly the selected leaf and also require its fingerprint. Standard TLS
	// hostname, lifetime and server-purpose checks stay enabled, including private CA tests.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	config := &tls.Config{ServerName: domain, RootCAs: roots, MinVersion: tls.VersionTLS12, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("HTTPS 未返回证书")
		}
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		if hex.EncodeToString(sum[:]) != cert.Fingerprint {
			return errors.New("实际 HTTPS 证书指纹与绑定不一致")
		}
		return nil
	}}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: config}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func verifySiteHTTPS(ctx context.Context, site core.Site) error {
	for _, domain := range append([]string{site.Domain}, site.Settings.Domains...) {
		if site.Status == "stopped" || site.Settings.TLS == nil {
			// Negative probe: any successful handshake is a failure. No peer is accepted
			// for application traffic; this deliberately detects even an untrusted leftover server.
			dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
			conn, e := dialer.DialContext(ctx, "tcp", "127.0.0.1:19102")
			if e == nil {
				conn.Close()
				return fmt.Errorf("未启用 HTTPS 的站点 %s 仍接受 TLS 握手", domain)
			}
			continue
		}
		client, e := siteHTTPSClient(site, domain)
		if e != nil {
			return e
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", siteURL(site, siteHealthPath(site)), nil)
		req.Host = domain
		resp, e := client.Do(req)
		if e != nil {
			client.CloseIdleConnections()
			return e
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		client.CloseIdleConnections()
		if e != nil {
			return e
		}
		if resp.StatusCode != 200 || string(b) != siteHealthBody(site) {
			return fmt.Errorf("域名 %s 未通过实际 HTTPS 入口验证", domain)
		}
		if site.Settings.TLS.Redirect {
			plain := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			path := "/__panel_tls_redirect_check?panel=1&path=%2F"
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101"+path, nil)
			req.Host = domain
			response, e := plain.Do(req)
			if e != nil {
				plain.CloseIdleConnections()
				return e
			}
			response.Body.Close()
			plain.CloseIdleConnections()
			if response.StatusCode != 301 || response.Header.Get("Location") != siteHTTPSRedirect(site, domain, path) {
				return fmt.Errorf("域名 %s 的 HTTPS 跳转未保留完整请求路径", domain)
			}
		}
	}
	return nil
}
