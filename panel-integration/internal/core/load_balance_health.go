package core

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

// LoadBalanceHTTPHealth is an opt-in observation policy, not authority to
// rewrite traffic routing. Targets are the entry's already validated IP nodes.
type LoadBalanceHTTPHealth struct {
	Path           string `json:"path"`
	Interval       int    `json:"interval"`
	TimeoutMS      int    `json:"timeout_ms"`
	ExpectedStatus int    `json:"expected_status"`
	BodyContains   string `json:"body_contains"`
	Failures       int    `json:"failures"`
	Successes      int    `json:"successes"`
}

func ValidateLoadBalanceHTTPHealth(v *LoadBalanceHTTPHealth) error {
	if v == nil {
		return nil
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
