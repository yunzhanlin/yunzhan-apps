package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	loadBalanceExportMaxBody    = 1 << 20
	loadBalanceExportMaxBytes   = 8 << 20
	loadBalanceExportMaxTickets = 32
	loadBalanceExportPerSession = 8
	loadBalanceExportTTL        = 5 * time.Minute
)

type loadBalanceReportExport struct {
	Owner    string
	Action   string
	SHA256   string
	Body     []byte
	Expires  time.Time
	Sequence uint64
}

// A receipt refers to exactly the decoded result sent by this Core, not a
// client-uploaded document or a later last-report.json. It grants no authority:
// every attachment request still needs the same live session and menu/role.
type LoadBalanceReportExportReceipt struct {
	Format    int    `json:"format"`
	Module    string `json:"module"`
	Action    string `json:"action"`
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
	ExpiresAt string `json:"expires_at"`
}

func loadBalanceExportOwner(u identity) string {
	if u.ID == "" || u.CSRF == "" {
		return ""
	}
	return Hash(u.ID + "\x00" + u.CSRF)
}

func loadBalanceExportAction(action string) bool {
	return action == "history" || ValidAppModuleAction("load-balance", action)
}

// Only the reviewed LB result family is enabled. Do not generalize this to
// credential-producing modules. Reject nested secrets and excessive structure.
func loadBalanceExportSafe(value any, depth int, visited *int) bool {
	*visited++
	if depth > 16 || *visited > 32768 {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch strings.ToLower(key) {
			case "password", "token", "secret", "private_key", "remote_private_key", "environment", "environment_patch", "report_export":
				return false
			}
			if !loadBalanceExportSafe(child, depth+1, visited) {
				return false
			}
		}
	case []any:
		for _, child := range v {
			if !loadBalanceExportSafe(child, depth+1, visited) {
				return false
			}
		}
	}
	return true
}

func (a *Server) removeLoadBalanceExportLocked(id string) {
	if entry, ok := a.reportExports[id]; ok {
		a.reportExportBytes -= len(entry.Body)
		delete(a.reportExports, id)
	}
}

func (a *Server) expireLoadBalanceExportsLocked(now time.Time) {
	for id, entry := range a.reportExports {
		if !now.Before(entry.Expires) {
			a.removeLoadBalanceExportLocked(id)
		}
	}
}

func (a *Server) oldestLoadBalanceExportLocked(owner string) string {
	id := ""
	var sequence uint64
	for key, entry := range a.reportExports {
		if owner != "" && entry.Owner != owner {
			continue
		}
		if id == "" || entry.Sequence < sequence {
			id, sequence = key, entry.Sequence
		}
	}
	return id
}

func (a *Server) withLoadBalanceReportExport(u identity, action string, value any, now time.Time) any {
	owner := loadBalanceExportOwner(u)
	if owner == "" || !loadBalanceExportAction(action) {
		return value
	}
	// Clone before adding metadata; never mutate the executor result or files.
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > loadBalanceExportMaxBody {
		return value
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil {
		return value
	}
	visited := 0
	if !loadBalanceExportSafe(object, 0, &visited) {
		return value
	}
	body, err := json.MarshalIndent(object, "", "  ")
	if err != nil || len(body)+1 > loadBalanceExportMaxBody {
		return value
	}
	body = append(body, '\n')
	digest := sha256.Sum256(body)
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return value
	}
	id := hex.EncodeToString(random[:])
	expires := now.Add(loadBalanceExportTTL)
	a.reportExportMu.Lock()
	defer a.reportExportMu.Unlock()
	if a.reportExports == nil {
		a.reportExports = make(map[string]loadBalanceReportExport)
	}
	a.expireLoadBalanceExportsLocked(now)
	if _, collision := a.reportExports[id]; collision {
		return value
	}
	count := 0
	for _, entry := range a.reportExports {
		if entry.Owner == owner {
			count++
		}
	}
	for count >= loadBalanceExportPerSession {
		a.removeLoadBalanceExportLocked(a.oldestLoadBalanceExportLocked(owner))
		count--
	}
	for len(a.reportExports) >= loadBalanceExportMaxTickets || a.reportExportBytes+len(body) > loadBalanceExportMaxBytes {
		a.removeLoadBalanceExportLocked(a.oldestLoadBalanceExportLocked(""))
	}
	a.reportExportSeq++
	sha := hex.EncodeToString(digest[:])
	a.reportExports[id] = loadBalanceReportExport{Owner: owner, Action: action, SHA256: sha, Body: body, Expires: expires, Sequence: a.reportExportSeq}
	a.reportExportBytes += len(body)
	object["report_export"] = LoadBalanceReportExportReceipt{Format: 1, Module: "load-balance", Action: action, ID: id, SHA256: sha, Bytes: len(body), ExpiresAt: expires.UTC().Format(time.RFC3339Nano)}
	return object
}

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func (a *Server) loadBalanceReportExportRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/{id}/report-export/{ticket}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, ticket := r.PathValue("id"), r.PathValue("ticket")
		query, queryError := url.ParseQuery(r.URL.RawQuery)
		if id != "load-balance" {
			fail(w, 404, "此应用未提供报告快照导出")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !a.originAllowed(r, origin) {
			fail(w, 403, "报告下载来源不被允许")
			return
		}
		if queryError != nil || !lowerHex(ticket, 32) || len(query) != 1 || len(query["sha256"]) != 1 || !lowerHex(query.Get("sha256"), 64) {
			fail(w, 400, "报告身份和摘要参数无效")
			return
		}
		now := time.Now()
		a.reportExportMu.Lock()
		a.expireLoadBalanceExportsLocked(now)
		entry, found := a.reportExports[ticket]
		if !found || entry.Owner != loadBalanceExportOwner(u) {
			a.reportExportMu.Unlock()
			fail(w, 410, "报告快照已失效，请重新查询当前页面")
			return
		}
		if entry.SHA256 != query.Get("sha256") {
			a.reportExportMu.Unlock()
			fail(w, 409, "报告摘要不匹配，拒绝导出其他结果")
			return
		}
		body := append([]byte(nil), entry.Body...)
		a.reportExportMu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="load-balance-`+entry.Action+`-report.json"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Content-SHA256", entry.SHA256)
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}
