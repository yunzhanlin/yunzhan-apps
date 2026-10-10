package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Observation remains the historical default. AutoTraffic is a separate,
// explicit opt-in authority; nil preserves the current value on an edit.
// Targets are the entry's already validated fixed IP nodes.
type LoadBalanceHTTPHealth struct {
	Path           string `json:"path"`
	Interval       int    `json:"interval"`
	TimeoutMS      int    `json:"timeout_ms"`
	ExpectedStatus int    `json:"expected_status"`
	BodyContains   string `json:"body_contains"`
	Failures       int    `json:"failures"`
	Successes      int    `json:"successes"`
	Scheme         string `json:"scheme,omitempty"`
	CAPEM          string `json:"ca_pem,omitempty"`
	CheckPort      int    `json:"check_port,omitempty"`
	AutoTraffic    *bool  `json:"auto_traffic,omitempty"`
}

func LoadBalanceAutomaticTraffic(v *LoadBalanceHTTPHealth) bool {
	return v != nil && v.AutoTraffic != nil && *v.AutoTraffic
}

// LoadBalanceHealthRoots accepts public CA certificates only, never private
// keys, filesystem paths or a request to bypass verification. A private pool
// applies to this entry alone; an empty value uses the host trust store.
func LoadBalanceHealthRoots(value string) (*x509.CertPool, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 16<<10 {
		return nil, errors.New("入口 CA 证书最多 16 KiB")
	}
	pool := x509.NewCertPool()
	remaining := []byte(strings.TrimSpace(value))
	count := 0
	for len(remaining) > 0 {
		if !strings.HasPrefix(string(remaining), "-----BEGIN CERTIFICATE-----") {
			return nil, errors.New("入口 CA 只接受 PEM 公共证书，不接受密钥或其他内容")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("入口 CA PEM 无效")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("入口 CA 必须是具有证书签名用途的有效 CA 公共证书")
		}
		count++
		if count > 4 {
			return nil, errors.New("每入口最多 4 个 CA 证书")
		}
		pool.AddCert(certificate)
		remaining = []byte(strings.TrimSpace(string(rest)))
	}
	if count == 0 {
		return nil, errors.New("入口 CA 证书为空")
	}
	return pool, nil
}

func ValidateLoadBalanceHTTPHealth(v *LoadBalanceHTTPHealth) error {
	if v == nil {
		return nil
	}
	if v.Scheme != "" && v.Scheme != "http" && v.Scheme != "https" {
		return errors.New("应用检查协议只允许 http 或 https")
	}
	if v.CheckPort < 0 || v.CheckPort > 65535 || (v.Scheme == "https" && v.CheckPort == 0) {
		return errors.New("HTTPS 检查须指定独立就绪端口（1–65535）；HTTP 检查可用 0 沿用转发端口")
	}
	if v.CAPEM != "" && v.Scheme != "https" {
		return errors.New("入口专用 CA 仅用于 HTTPS 检查")
	}
	if _, err := LoadBalanceHealthRoots(v.CAPEM); err != nil {
		return err
	}
	if len(v.Path) < 1 || len(v.Path) > 512 || !strings.HasPrefix(v.Path, "/") ||
		strings.HasPrefix(v.Path, "//") || strings.ContainsAny(v.Path, "#\\") ||
		v.Interval < 30 || v.Interval > 3600 || v.TimeoutMS < 500 || v.TimeoutMS > 5000 ||
		v.ExpectedStatus < 200 || v.ExpectedStatus > 299 || v.Failures < 1 || v.Failures > 10 ||
		v.Successes < 1 || v.Successes > 10 || len(v.BodyContains) > 256 ||
		!utf8.ValidString(v.BodyContains) || strings.ContainsRune(v.BodyContains, 0) {
		return errors.New("HTTP 检查须使用 / 开头的相对路径、30–3600 秒间隔、500–5000 毫秒超时、2xx 状态、1–10 次失败/恢复阈值及最多 256 字节内容")
	}
	for _, c := range []byte(v.Path) {
		if c < 33 || c > 126 {
			return errors.New("HTTP 检查路径只接受无空白的 ASCII 请求路径")
		}
	}
	u, err := url.ParseRequestURI(v.Path)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" {
		return errors.New("HTTP 检查路径不允许完整 URL、凭据或片段")
	}
	decoded, err := url.QueryUnescape(v.Path)
	if err != nil || strings.ContainsAny(decoded, "\x00\r\n") {
		return errors.New("HTTP 检查路径存在非法转义或控制字节")
	}
	for _, c := range []byte(decoded) {
		if c < 32 || c == 127 {
			return errors.New("HTTP 检查路径不允许转义控制字节")
		}
	}
	return nil
}
