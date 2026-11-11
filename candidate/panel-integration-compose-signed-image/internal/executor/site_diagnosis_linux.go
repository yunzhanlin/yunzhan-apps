//go:build linux

package executor

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

func diagnosisPath(value string) (string, error) {
	if value == "" {
		return "/", nil
	}
	clean := strings.TrimSuffix(value, "/")
	if clean == "" {
		clean = "/"
	}
	if len(value) > 512 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") ||
		strings.ContainsAny(value, "?#%\\") || strings.Contains(value, "//") ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 || path.Clean(clean) != clean ||
		strings.HasPrefix(value, "/__panel_health_") {
		return "", errors.New("请输入该网站的绝对路径，不含查询参数、片段或编码分隔符")
	}
	return value, nil
}

func diagnosisOrder(symptom string) ([]string, error) {
	common := []string{"binding", "http", "dns", "tls_certificate", "nginx", "files"}
	var first string
	switch symptom {
	case "", "all":
		return common, nil
	case "timeout":
		first = "dns"
	case "https":
		first = "tls_certificate"
	case "permission":
		first = "files"
	case "not-found", "server-error", "slow":
		first = "http"
	default:
		return nil, errors.New("未知的网站故障现象")
	}
	ordered := []string{first}
	for _, item := range common {
		if item != first {
			ordered = append(ordered, item)
		}
	}
	return ordered, nil
}

func diagnosisHTTP(ctx context.Context, client *http.Client, domain, probePath string) (*http.Response, int64, error) {
	endpoint := url.URL{Scheme: "http", Host: "127.0.0.1:19101", Path: probePath}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Host = domain
	start := time.Now()
	response, err := client.Do(req)
	return response, time.Since(start).Milliseconds(), err
}

func diagnosisHTTPResult(status int, elapsed int64, err error) map[string]any {
	if err != nil {
		return map[string]any{"ok": false, "verdict": "fail", "response_ms": elapsed,
			"detail": "站点入口未能返回 HTTP 响应。检查入口服务、监听和连接超时。"}
	}
	verdict := "fail"
	var detail string
	switch {
	case status >= 200 && status < 300 && elapsed < 1500:
		verdict, detail = "pass", "站点返回成功响应。"
	case status >= 200 && status < 300:
		verdict, detail = "warn", "站点可用，但响应首部超过 1.5 秒。可查看慢请求和后端负载。"
	case status >= 300 && status < 400:
		verdict, detail = "warn", "站点返回重定向。请核对目标协议和域名。"
	case status == http.StatusForbidden:
		detail = "请求被拒绝。检查网站文件权限、访问规则和防火墙日志。"
	case status == http.StatusNotFound:
		detail = "测试路径不存在。检查站点绑定、运行目录和 URL 改写。"
	case status == http.StatusBadGateway:
		detail = "入口无法从后端取得有效响应。检查 PHP-FPM 或反向代理服务与套接字。"
	case status == http.StatusServiceUnavailable:
		detail = "服务暂时不可用。检查维护状态、运行池和服务器资源。"
	case status == http.StatusGatewayTimeout:
		detail = "后端响应超时。检查慢请求、数据库和上游服务。"
	case status >= 500:
		detail = "站点返回服务器错误。检查网站和应用错误日志。"
	default:
		detail = "站点拒绝了测试请求。请核对路径和访问策略。"
	}
	return map[string]any{"ok": verdict == "pass", "verdict": verdict, "status": status, "response_ms": elapsed, "detail": detail}
}

func diagnosisTLS(ctx context.Context, domain string) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return map[string]any{"valid": false, "verdict": "fail", "detail": "域名的 HTTPS 握手或证书校验失败。", "error": err.Error()}
	}
	defer conn.Close()
	certificates := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return map[string]any{"valid": false, "verdict": "fail", "detail": "HTTPS 服务未返回可核验的证书。"}
	}
	certificate := certificates[0]
	verdict := "pass"
	detail := "已验证证书链及站点域名。"
	if time.Until(certificate.NotAfter) < 14*24*time.Hour {
		verdict, detail = "warn", "证书在 14 天内到期，请检查续签。"
	}
	return map[string]any{"valid": true, "verdict": verdict, "detail": detail,
		"not_after": certificate.NotAfter.UTC().Format(time.RFC3339), "issuer": certificate.Issuer.String()}
}

func (s *Service) moduleDiagnosis(ctx context.Context, input core.AppModuleInput) (any, error) {
	probePath, err := diagnosisPath(input.Path)
	if err != nil {
		return nil, err
	}
	order, err := diagnosisOrder(input.DiagnosisSymptom)
	if err != nil {
		return nil, err
	}
	files, err := s.openFiles(input.SiteID)
	if err != nil {
		return nil, err
	}
	defer files.Close()
	raw, err := files.root.ReadFile(".panel-site.json")
	if err != nil {
		return nil, err
	}
	var marker struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	}
	if json.Unmarshal(raw, &marker) != nil || marker.ID != input.SiteID || !core.ValidDomain(marker.Domain) {
		return nil, errors.New("站点标识或域名无法核对")
	}

	apacheDomain, apache := input.DiagnosisApacheSites[marker.ID]
	if apache && !strings.EqualFold(apacheDomain, marker.Domain) {
		return nil, errors.New("面板登记的站点域名与执行器站点标识不一致")
	}

	budget := 24 * time.Second
	if apache {
		budget += 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	checks := make(map[string]map[string]any, len(order))
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 3*time.Second)
	addresses, dnsErr := net.DefaultResolver.LookupHost(dnsCtx, marker.Domain)
	dnsCancel()
	dnsVerdict, dnsDetail := "pass", "本机解析器返回了域名地址。"
	if dnsErr != nil || len(addresses) == 0 {
		dnsVerdict, dnsDetail = "fail", "本机无法解析站点域名。检查 DNS 记录和解析器。"
	}
	if len(addresses) > 32 {
		addresses = addresses[:32]
	}
	checks["dns"] = map[string]any{"ok": dnsVerdict == "pass", "verdict": dnsVerdict, "detail": dnsDetail, "addresses": addresses}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	health, _, healthErr := diagnosisHTTP(ctx, client, marker.Domain, siteHealthPath(core.Site{ID: marker.ID}))
	bindingVerdict, bindingDetail := "fail", "入口未返回此站点的身份校验响应。请核对域名绑定、站点状态和当前配置。"
	if healthErr == nil {
		body, readErr := io.ReadAll(io.LimitReader(health.Body, 129))
		health.Body.Close()
		prefix := "panel:" + marker.ID + ":"
		identity := string(body)
		digest, found := strings.CutPrefix(identity, prefix)
		decoded, digestErr := hex.DecodeString(digest)
		if readErr == nil && health.StatusCode == http.StatusOK && found && digestErr == nil &&
			len(decoded) == 32 && health.Header.Get("X-Panel-Config") == core.Hash(identity) {
			bindingVerdict, bindingDetail = "pass", "实际入口响应与该受管站点的标识一致。"
		} else if health.StatusCode == http.StatusNotFound {
			bindingVerdict, bindingDetail = "warn", "入口未返回站点校验标记。站点可能停用，或仍使用旧配置。"
		}
	}
	checks["binding"] = map[string]any{"ok": bindingVerdict == "pass", "verdict": bindingVerdict, "detail": bindingDetail}
	response, elapsed, httpErr := diagnosisHTTP(ctx, client, marker.Domain, probePath)
	var code int
	if httpErr == nil {
		code = response.StatusCode
		response.Body.Close()
	}
	checks["http"] = diagnosisHTTPResult(code, elapsed, httpErr)

	nginxCtx, nginxCancel := context.WithTimeout(ctx, 4*time.Second)
	output, configErr := s.Config.Run(nginxCtx, s.Config.NginxBin, "-t")
	nginxCancel()
	if len(output) > 4096 {
		output = output[:4096]
	}
	nginxVerdict, nginxDetail := "pass", "Nginx 当前配置通过语法检查。"
	if configErr != nil {
		nginxVerdict, nginxDetail = "fail", "Nginx 当前配置未通过语法检查。"
	}
	checks["nginx"] = map[string]any{"ok": configErr == nil, "verdict": nginxVerdict, "detail": nginxDetail, "output": output}
	if apache {
		order = append(order, "apache_config", "apache_listener")
		checks["apache_config"], checks["apache_listener"] = s.diagnoseApache(ctx, marker.ID, apacheDomain)
	}
	checks["tls_certificate"] = diagnosisTLS(ctx, marker.Domain)

	scan, scanErr := inspectSiteFiles(files)
	fileVerdict, fileDetail := "pass", "已抽查站点目录和文件权限。"
	if scanErr != nil {
		fileVerdict, fileDetail = "fail", "无法读取站点文件。检查运行目录是否存在及目录权限。"
	} else if scan.Status != "safe" {
		fileVerdict, fileDetail = "warn", "文件抽查有告警或覆盖范围有限，查看具体记录。"
	}
	checks["files"] = map[string]any{"ok": fileVerdict == "pass", "verdict": fileVerdict, "detail": fileDetail, "scan": scan}
	passed := 0
	scope := "HTTP 与域名绑定由面板服务器在本机入口验证，TLS 使用该服务器解析到的域名地址。"
	if _, apache := checks["apache_config"]; apache {
		scope += " Apache 检查读取磁盘上的受管配置并核对进程监听。所选路径通过 Nginx 入口请求。"
	}
	recommendations := []map[string]any{}
	for _, key := range order {
		check := checks[key]
		if check["verdict"] == "pass" {
			passed++
		} else {
			recommendations = append(recommendations, map[string]any{"check": key, "advice": check["detail"]})
		}
	}
	return map[string]any{"site_id": marker.ID, "domain": marker.Domain, "path": probePath,
		"diagnosis_symptom": input.DiagnosisSymptom, "checked_at": core.Now(), "check_order": order, "checks": checks,
		"passed_checks": passed, "total_checks": len(order), "score": passed * 100 / len(order),
		"recommendations": recommendations, "scope": scope}, nil
}

func (s *Service) moduleDiagnosisBatch(ctx context.Context, input core.AppModuleInput) (any, error) {
	if len(input.SiteIDs) < 1 || len(input.SiteIDs) > 4 {
		return nil, errors.New("请选择 1 至 4 个站点")
	}
	seen := map[string]bool{}
	for _, id := range input.SiteIDs {
		if !core.ValidID(id) || seen[id] {
			return nil, errors.New("站点标识无效或重复")
		}
		seen[id] = true
	}
	if _, err := diagnosisPath(input.Path); err != nil {
		return nil, err
	}
	if _, err := diagnosisOrder(input.DiagnosisSymptom); err != nil {
		return nil, err
	}
	type batchRow struct {
		SiteID string `json:"site_id"`
		Report any    `json:"report,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	rows := make([]batchRow, len(input.SiteIDs))
	for start := 0; start < len(rows); start += 2 {
		var workers sync.WaitGroup
		for i := start; i < min(start+2, len(rows)); i++ {
			workers.Go(func() {
				id := input.SiteIDs[i]
				report, err := s.moduleDiagnosis(ctx, core.AppModuleInput{SiteID: id, Path: input.Path, DiagnosisSymptom: input.DiagnosisSymptom,
					DiagnosisApacheSites: input.DiagnosisApacheSites})
				rows[i] = batchRow{SiteID: id, Report: report}
				if err != nil {
					rows[i].Error = err.Error()
				}
			})
		}
		workers.Wait()
	}
	return map[string]any{"diagnoses": rows, "checked_at": core.Now(), "site_count": len(rows)}, nil
}
