//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const ftpTransferJournalLimit = 1000
const ftpTransferUnit = "panel-pure-ftpd.service"

var ftpTransferMessage = regexp.MustCompile(`^\(([a-z][a-z0-9-]{2,31})@([^ )]+)\) \[NOTICE\] (/[^\r\n]+) (uploaded|downloaded)  \(([0-9]{1,20}) bytes, ([0-9]{1,16}\.[0-9]{2})KB/sec\)$`)

type ftpTransferJournalEntry struct {
	Time       string          `json:"__REALTIME_TIMESTAMP"`
	Unit       string          `json:"_SYSTEMD_UNIT"`
	Executable string          `json:"_EXE"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	Transport  string          `json:"_TRANSPORT"`
	Message    json.RawMessage `json:"MESSAGE"`
}

func parseFTPTransfer(entry ftpTransferJournalEntry, executable, sitesDir string) (core.FTPTransferRecord, bool) {
	if entry.Unit != ftpTransferUnit || entry.Executable != executable || entry.Identifier != "pure-ftpd" ||
		entry.Transport != "syslog" || len(entry.Message) > 8192 {
		return core.FTPTransferRecord{}, false
	}
	var message string
	if json.Unmarshal(entry.Message, &message) != nil || len(message) > 4096 || !utf8.ValidString(message) {
		return core.FTPTransferRecord{}, false
	}
	parts := ftpTransferMessage.FindStringSubmatch(message)
	if parts == nil {
		return core.FTPTransferRecord{}, false
	}
	address, err := netip.ParseAddr(parts[2])
	if err != nil || !address.Unmap().Is4() {
		return core.FTPTransferRecord{}, false
	}
	root := strings.TrimSuffix(sitesDir, "/")
	file, ok := strings.CutPrefix(parts[3], root+"/")
	if root == "" || !ok {
		return core.FTPTransferRecord{}, false
	}
	site, file, ok := strings.Cut(file, "/public/")
	file = strings.TrimLeft(file, "/")
	if !ok || !core.ValidID(site) || file == "" || len(file) > 1024 || path.Clean(file) != file ||
		file == "." || file == ".." || strings.HasPrefix(file, "../") || strings.ContainsFunc(file, unicode.IsControl) {
		return core.FTPTransferRecord{}, false
	}
	micros, timeErr := strconv.ParseInt(entry.Time, 10, 64)
	size, sizeErr := strconv.ParseUint(parts[5], 10, 64)
	speed, speedErr := strconv.ParseFloat(parts[6], 64)
	if timeErr != nil || micros <= 0 || sizeErr != nil || speedErr != nil {
		return core.FTPTransferRecord{}, false
	}
	direction := "download"
	if parts[4] == "uploaded" {
		direction = "upload"
	}
	return core.FTPTransferRecord{Time: time.UnixMicro(micros).UTC(), SiteID: site, Username: parts[1],
		ClientIP: address.Unmap().String(), Direction: direction, Path: "/" + file, Bytes: size, KiBPerSecond: speed}, true
}

func ftpTransferRecords(raw []byte, executable, sitesDir string, query core.FTPTransferQuery, from, to time.Time) (core.FTPTransferHistory, error) {
	report := core.FTPTransferHistory{From: from, To: to, Events: make([]core.FTPTransferRecord, 0, query.Limit), SourceLimit: ftpTransferJournalLimit}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > ftpTransferJournalLimit {
			return report, errors.New("传输日志源记录超过核对上限")
		}
		var entry ftpTransferJournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return report, errors.New("传输日志记录格式无法核对")
		}
		record, ok := parseFTPTransfer(entry, executable, sitesDir)
		if !ok || record.Time.Before(from) || record.Time.After(to) ||
			query.Username != "" && query.Username != record.Username ||
			query.Direction != "" && query.Direction != record.Direction ||
			query.SiteID != "" && query.SiteID != record.SiteID {
			continue
		}
		if len(report.Events) == query.Limit {
			report.HasMore = true
			continue
		}
		report.Events = append(report.Events, record)
	}
	if err := scanner.Err(); err != nil {
		return report, errors.New("传输日志行过长，未返回不完整结果")
	}
	report.HasMore = report.HasMore || lines == ftpTransferJournalLimit
	return report, nil
}

func (s *Service) readFTPTransferHistory(ctx context.Context, query core.FTPTransferQuery) (core.FTPTransferHistory, error) {
	record, err := s.moduleInstalledRecord("pure-ftpd")
	if err != nil || record["version"] != appcatalog.FTPTransferHistoryVersion {
		return core.FTPTransferHistory{}, errors.New("请先签名安装或更新支持传输日志的 Pure-FTPd")
	}
	binary, err := s.ftpBinary("pure-ftpd")
	if err != nil || binary != s.systemPath(path.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion, "pure-ftpd")) {
		return core.FTPTransferHistory{}, errors.New("受管 FTP 可执行文件无法核对，未读取传输日志")
	}
	to := time.Now().UTC().Truncate(time.Microsecond)
	if !query.End.IsZero() {
		if query.End.After(to) {
			return core.FTPTransferHistory{}, errors.New("传输日志结束时间不能晚于当前时间")
		}
		to = query.End.Truncate(time.Microsecond)
	}
	from := to.Add(-time.Duration(query.Minutes) * time.Minute)
	asJournalTime := func(t time.Time) string {
		return fmt.Sprintf("@%d.%06d", t.Unix(), t.Nanosecond()/1000)
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/journalctl", "--no-pager", "--quiet", "--reverse",
		"--output=json", "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_EXE,SYSLOG_IDENTIFIER,_TRANSPORT,MESSAGE",
		"--lines="+strconv.Itoa(ftpTransferJournalLimit), "--since="+asJournalTime(from), "--until="+asJournalTime(to),
		"_SYSTEMD_UNIT="+ftpTransferUnit, "_EXE="+binary, "_TRANSPORT=syslog", "SYSLOG_IDENTIFIER=pure-ftpd", "PRIORITY=5")
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdout, stderr := &boundedBuffer{max: 4 << 20}, &boundedBuffer{max: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err = command.Run(); err != nil || stdout.truncated {
		return core.FTPTransferHistory{}, errors.New("无法完整读取受管 FTP 日志")
	}
	return ftpTransferRecords(stdout.Bytes(), binary, s.Config.SitesDir, query, from, to)
}

func (s *Service) ftpTransferHistoryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/pure-ftpd/transfers", func(w http.ResponseWriter, r *http.Request) {
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			respond(w, http.StatusBadRequest, map[string]string{"error": "传输日志筛选条件无效"})
			return
		}
		query, err := core.ParseFTPTransferQuery(values)
		if err != nil {
			respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		report, err := s.readFTPTransferHistory(r.Context(), query)
		if err != nil {
			respond(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		respond(w, http.StatusOK, report)
	})
}
