//go:build linux

package executor

import (
	"local/panel/internal/core"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

func inspectSiteFiles(f *siteFiles) (core.SiteSecurityScan, error) {
	out := core.SiteSecurityScan{Status: "safe", Findings: []core.SiteSecurityFinding{}}
	const maxDirectories, maxEntries = 24, 1200
	type pendingDirectory struct {
		path  string
		depth int
	}
	queue := []pendingDirectory{{path: "", depth: 0}}
	visited, scanned := 0, 0
	partial := false
	add := func(path, rule, severity, description string) {
		if len(out.Findings) >= 20 {
			return
		}
		out.Findings = append(out.Findings, core.SiteSecurityFinding{Path: path, Rule: rule, Severity: severity, Description: description})
	}
	for len(queue) > 0 && visited < maxDirectories && scanned < maxEntries {
		current := queue[0]
		queue = queue[1:]
		listing, e := f.List(current.path, "")
		if e != nil {
			if current.depth == 0 {
				return out, e
			}
			partial = true
			continue
		}
		visited++
		if listing["truncated"] == true {
			partial = true
		}
		if meta, ok := listing["directory"].(core.FileEntry); ok {
			perm, _ := strconv.ParseUint(meta.Mode, 8, 16)
			if perm&0002 != 0 {
				path := current.path
				if path == "" {
					path = "/"
				}
				add(path, "world_writable", "warning", "公开目录允许其他系统用户写入")
			}
		}
		entries := listing["entries"].([]core.FileEntry)
		if len(entries) > maxEntries-scanned {
			entries = entries[:maxEntries-scanned]
			partial = true
		}
		scanned += len(entries)
		for _, entry := range entries {
			name := strings.ToLower(entry.Name)
			path := filepath.Clean(entry.Path)
			switch {
			case entry.Kind == "file" && (name == ".env" || strings.HasPrefix(name, ".env.")) && !strings.HasSuffix(name, ".example"):
				add(path, "environment_file", "high", "环境配置文件位于网站公开目录，需核对 Web 服务器访问策略")
			case entry.Kind == "directory" && (name == ".git" || name == ".svn"):
				add(path, "repository_metadata", "high", "版本库元数据位于网站公开目录")
			case entry.Kind == "file" && name == "phpinfo.php":
				add(path, "phpinfo", "warning", "phpinfo 页面可能暴露 PHP 环境信息")
			case entry.Kind == "file" && (name == "id_rsa" || strings.HasSuffix(name, ".key")):
				add(path, "private_key", "high", "疑似私钥文件位于网站公开目录")
			case entry.Kind == "file" && (strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".sql.gz")) && (strings.Contains(name, "backup") || strings.Contains(name, "dump") || strings.Contains(name, "database")):
				add(path, "database_backup", "high", "数据库备份位于网站公开目录")
			case entry.Kind == "file" && (strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".old") || strings.HasSuffix(name, "~")):
				add(path, "backup_copy", "warning", "备份副本位于网站公开目录")
			}
			if entry.Kind == "directory" && current.depth < 2 && name != ".git" && name != ".svn" {
				queue = append(queue, pendingDirectory{path: path, depth: current.depth + 1})
			} else if entry.Kind == "directory" && current.depth >= 2 {
				partial = true
			}
		}
	}
	if len(queue) > 0 {
		partial = true
	}
	if len(out.Findings) > 0 {
		out.Status = "attention"
	}
	if partial || len(out.Findings) == 20 {
		out.Status = "partial"
	}
	return out, nil
}

func (s *Service) siteSecurityScanRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/sites/{id}/security-scan", func(w http.ResponseWriter, r *http.Request) {
		f, e := s.openFiles(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "网站目录不可用"})
			return
		}
		defer f.Close()
		scan, e := inspectSiteFiles(f)
		if e != nil {
			respond(w, 409, map[string]string{"error": "网站目录扫描失败"})
			return
		}
		respond(w, 200, scan)
	})
}
