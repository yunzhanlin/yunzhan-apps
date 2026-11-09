package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const platformHealthBytes = 256 << 10

func platformHealthClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.TLSHandshakeTimeout = 3 * time.Second
	transport.ResponseHeaderTimeout = 3 * time.Second
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// No remote body or transport error is echoed: it may contain credentials or
// arbitrary HTML. A valid protocol response does not make every metric known.
func readPlatformHealth(ctx context.Context, client *http.Client, id, address, token string) map[string]any {
	entry := map[string]any{"id": id, "url": address, "healthy": false, "telemetry_complete": false}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || len(address) > 2048 {
		entry["error"] = "登记地址不是可核对的 HTTPS 地址；未发出请求"
		return entry
	}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(address, "/")+"/api/platform/agent", nil)
	if err != nil {
		entry["error"] = "登记地址无法构造只读请求"
		return entry
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	before := time.Now()
	response, err := client.Do(req)
	if err != nil {
		entry["error"] = "HTTPS 连接、证书或读取期限未通过；未认定健康"
		return entry
	}
	defer response.Body.Close()
	entry["status"] = response.StatusCode
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		entry["error"] = "远端状态码或 JSON 媒体类型不符合健康协议"
		return entry
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, platformHealthBytes+1))
	if err != nil || len(raw) > platformHealthBytes {
		entry["error"] = "远端健康响应不完整或超过 256 KiB；未使用部分数据"
		return entry
	}
	report, complete, err := decodePlatformHealth(raw, before, time.Now())
	if err != nil {
		entry["error"] = "远端健康协议、时间或指标无法核对；未使用部分数据"
		return entry
	}
	entry["healthy"], entry["report"], entry["telemetry_complete"] = true, report, complete
	return entry
}

func decodePlatformHealth(raw []byte, before, after time.Time) (map[string]any, bool, error) {
	invalid := errors.New("健康协议无法核对")
	if len(raw) < 2 || len(raw) > platformHealthBytes || !utf8.Valid(raw) {
		return nil, false, invalid
	}
	// encoding/json v1 accepts duplicate names and a first valid prefix. Walk
	// exactly one bounded value first, including case/escaped-name collisions.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 8 || nodes > 4096 {
			return invalid
		}
		token, err := d.Token()
		if err != nil {
			return invalid
		}
		if delimiter, ok := token.(json.Delim); ok {
			if depth == 0 && delimiter != '{' {
				return invalid
			}
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					key, ok := token.(string)
					if err != nil || !ok || seen[strings.ToLower(key)] {
						return invalid
					}
					seen[strings.ToLower(key)] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return invalid
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return invalid
			}
		} else if depth == 0 {
			return invalid
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, false, invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false, invalid
	}
	var report map[string]any
	if json.Unmarshal(raw, &report) != nil || len(report) != 3 || report["version"] != "app-modules-1" {
		return nil, false, invalid
	}
	stamp, ok := report["time"].(string)
	if !ok {
		return nil, false, invalid
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil || at.Before(before.Add(-2*time.Minute)) || at.After(after.Add(30*time.Second)) {
		return nil, false, invalid
	}
	health, ok := report["health"].(map[string]any)
	if !ok || health == nil {
		return nil, false, invalid
	}
	textFields := map[string]bool{"os": true, "arch": true, "hostname": true, "kernel": true, "boot_id": true, "load": true, "sampled_at": true}
	integers := map[string]bool{"cpu_cores": true, "cpu_total": true, "cpu_idle": true, "memory_total": true, "memory_used": true, "disk_total": true, "disk_used": true, "disk_available": true, "network_rx": true, "network_tx": true, "disk_read_bytes": true, "disk_write_bytes": true}
	percentFlags := map[string]string{"cpu_percent": "cpu_available", "memory_percent": "memory_available", "disk_percent": "disk_percent_available"}
	for key, value := range health {
		switch {
		case textFields[key]:
			text, ok := value.(string)
			if !ok || len(text) > 256 || strings.ContainsAny(text, "\x00\r\n") {
				return nil, false, invalid
			}
		case integers[key]:
			n, ok := value.(float64)
			if !ok || n < 0 || n > 9007199254740991 || math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
				return nil, false, invalid
			}
		case key == "cpu_available" || key == "memory_available" || key == "disk_percent_available" || key == "nginx_active":
			if _, ok := value.(bool); !ok {
				return nil, false, invalid
			}
		case percentFlags[key] != "":
			if value != nil {
				n, ok := value.(float64)
				if !ok || n < 0 || n > 100 || math.IsNaN(n) || math.IsInf(n, 0) {
					return nil, false, invalid
				}
			}
		case key == "uptime_seconds" || key == "load_1":
			n, ok := value.(float64)
			if !ok || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
				return nil, false, invalid
			}
		default:
			return nil, false, invalid
		}
	}
	if health["os"] == nil || health["os"] == "" || (health["arch"] != "amd64" && health["arch"] != "arm64") {
		return nil, false, invalid
	}
	if _, ok := health["nginx_active"].(bool); !ok {
		return nil, false, invalid
	}
	sampled, ok := health["sampled_at"].(string)
	if !ok {
		return nil, false, invalid
	}
	sampleTime, err := time.Parse(time.RFC3339, sampled)
	if err != nil || sampleTime.Before(before.Add(-2*time.Minute)) || sampleTime.After(after.Add(30*time.Second)) {
		return nil, false, invalid
	}
	cores, ok := health["cpu_cores"].(float64)
	if !ok || cores < 1 || cores > 65536 {
		return nil, false, invalid
	}
	complete := true
	for key, flag := range percentFlags {
		available, ok := health[flag].(bool)
		value, present := health[key]
		if !ok || !present || available && value == nil || !available && value != nil {
			return nil, false, invalid
		}
		complete = complete && available
	}
	for _, pair := range [][2]string{{"memory_total", "memory_used"}, {"disk_total", "disk_used"}} {
		flag := "memory_available"
		if pair[0] == "disk_total" {
			flag = "disk_percent_available"
		}
		if health[flag] == true {
			total, tok := health[pair[0]].(float64)
			used, uok := health[pair[1]].(float64)
			if !tok || !uok || total <= 0 || used > total {
				return nil, false, invalid
			}
		}
	}
	return report, complete, nil
}
