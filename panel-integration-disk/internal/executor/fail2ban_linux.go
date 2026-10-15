//go:build linux

package executor

import (
	"encoding/json"
	"io"
	"local/panel/internal/core"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var validFail2banJail = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func parseFail2banJails(output string) []string {
	for _, line := range strings.Split(output, "\n") {
		if _, value, ok := strings.Cut(line, "Jail list:"); ok {
			out := []string{}
			for _, name := range strings.Split(value, ",") {
				name = strings.TrimSpace(name)
				if validFail2banJail.MatchString(name) && len(out) < 20 {
					out = append(out, name)
				}
			}
			return out
		}
	}
	return []string{}
}
func parseFail2banJail(name, output string) core.Fail2banJail {
	out := core.Fail2banJail{Name: name, BannedIPs: []string{}}
	for _, line := range strings.Split(output, "\n") {
		if _, value, ok := strings.Cut(line, "Currently banned:"); ok {
			out.CurrentlyBanned, _ = strconv.Atoi(strings.TrimSpace(value))
		}
		if _, value, ok := strings.Cut(line, "Total banned:"); ok {
			out.TotalBanned, _ = strconv.Atoi(strings.TrimSpace(value))
		}
		if _, value, ok := strings.Cut(line, "Banned IP list:"); ok {
			for _, text := range strings.Fields(value) {
				if ip, e := netip.ParseAddr(text); e == nil && len(out.BannedIPs) < 500 {
					out.BannedIPs = append(out.BannedIPs, ip.Unmap().String())
				}
			}
		}
	}
	return out
}

func (s *Service) fail2banStatus(r *http.Request) core.Fail2banStatus {
	out := core.Fail2banStatus{Jails: []core.Fail2banJail{}}
	if _, e := exec.LookPath("fail2ban-client"); e != nil {
		out.Detail = "Fail2ban 未安装"
		return out
	}
	out.Installed = true
	status, e := s.Config.Run(r.Context(), "systemctl", "is-active", "fail2ban")
	if e != nil || strings.TrimSpace(status) != "active" {
		out.Detail = "Fail2ban 服务未运行"
		return out
	}
	out.Active = true
	output, e := s.Config.Run(r.Context(), "fail2ban-client", "status")
	if e != nil {
		out.Detail = "Fail2ban 状态不可读取"
		return out
	}
	for _, name := range parseFail2banJails(output) {
		status, err := s.Config.Run(r.Context(), "fail2ban-client", "status", name)
		if err == nil {
			out.Jails = append(out.Jails, parseFail2banJail(name, status))
		}
	}
	return out
}
func (s *Service) fail2banRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/security/fail2ban", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, s.fail2banStatus(r)) })
	m.HandleFunc("POST /v1/security/fail2ban/unban", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Jail string `json:"jail"`
			IP   string `json:"ip"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validFail2banJail.MatchString(input.Jail) {
			respond(w, 400, map[string]string{"error": "无效解封请求"})
			return
		}
		ip, e := netip.ParseAddr(input.IP)
		if e != nil {
			respond(w, 400, map[string]string{"error": "无效 IP 地址"})
			return
		}
		input.IP = ip.Unmap().String()
		status := s.fail2banStatus(r)
		if !status.Active {
			respond(w, 409, map[string]string{"error": "Fail2ban 未运行"})
			return
		}
		found := false
		for _, jail := range status.Jails {
			if jail.Name != input.Jail {
				continue
			}
			for _, banned := range jail.BannedIPs {
				if banned == input.IP {
					found = true
					break
				}
			}
		}
		if !found {
			respond(w, 404, map[string]string{"error": "该 IP 不在当前封禁列表中"})
			return
		}
		if _, e = s.Config.Run(r.Context(), "fail2ban-client", "set", input.Jail, "unbanip", input.IP); e != nil {
			respond(w, 409, map[string]string{"error": "Fail2ban 解封失败"})
			return
		}
		respond(w, 200, map[string]any{"jail": input.Jail, "ip": input.IP, "unbanned": true})
	})
}
