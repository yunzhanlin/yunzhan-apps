package executor

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type monitoredServiceRequest struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
}

type monitoredServiceResult struct {
	Kind        string `json:"kind"`
	ResourceID  string `json:"resource_id"`
	ActualState string `json:"actual_state"`
	LoadState   string `json:"load_state"`
	SubState    string `json:"sub_state"`
}

var (
	phpServiceID    = regexp.MustCompile(`^[a-f0-9]{32}-php-[0-9]+\.[0-9]+\.[0-9]+(?:-cfg-[a-f0-9]{24})?$`)
	monitorObjectID = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

func monitoredUnit(v monitoredServiceRequest) (string, error) {
	switch v.Kind {
	case "nginx":
		if v.ResourceID != "nginx" {
			return "", errors.New("Nginx 服务标识无效")
		}
		return "nginx.service", nil
	case "php":
		if !phpServiceID.MatchString(v.ResourceID) {
			return "", errors.New("PHP 服务标识无效")
		}
		return "panel-php@" + v.ResourceID + ".service", nil
	case "mysql":
		if !monitorObjectID.MatchString(v.ResourceID) {
			return "", errors.New("MySQL 服务标识无效")
		}
		return "panel-mysql@" + v.ResourceID + ".service", nil
	default:
		return "", errors.New("不支持的服务类型")
	}
}

func parseSystemdProperties(raw string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, block := range strings.Split(strings.TrimSpace(raw), "\n\n") {
		properties := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				properties[key] = value
			}
		}
		if properties["Id"] != "" {
			out[properties["Id"]] = properties
		}
	}
	return out
}

func (s *Service) monitorServiceRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/monitor/services", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Services []monitoredServiceRequest `json:"services"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if len(in.Services) == 0 || len(in.Services) > 500 {
			respond(w, 400, map[string]string{"error": "服务清单数量无效"})
			return
		}
		units := make([]string, 0, len(in.Services))
		seen := map[string]bool{}
		for _, service := range in.Services {
			unit, err := monitoredUnit(service)
			if err != nil || seen[unit] {
				respond(w, 400, map[string]string{"error": "服务清单包含无效或重复项"})
				return
			}
			seen[unit] = true
			units = append(units, unit)
		}
		args := []string{"show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState"}
		args = append(args, units...)
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		raw, err := s.Config.Run(ctx, "/usr/bin/systemctl", args...)
		if err != nil {
			respond(w, 503, map[string]string{"error": "无法读取受管服务状态"})
			return
		}
		properties := parseSystemdProperties(raw)
		out := make([]monitoredServiceResult, 0, len(in.Services))
		for i, service := range in.Services {
			p := properties[units[i]]
			state := p["ActiveState"]
			if state == "" {
				state = "unknown"
			}
			out = append(out, monitoredServiceResult{Kind: service.Kind, ResourceID: service.ResourceID, ActualState: state, LoadState: p["LoadState"], SubState: p["SubState"]})
		}
		respond(w, 200, map[string]any{"services": out})
	})
}
