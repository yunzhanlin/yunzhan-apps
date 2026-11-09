//go:build linux

package executor

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxTrafficLogBytes int64 = 16 << 20
const maxTrafficRequestBytes int64 = 128 << 20

var trafficZone = time.FixedZone("UTC+8", 8*3600)

type trafficLine struct {
	Time  string `json:"time"`
	Bytes int64  `json:"bytes"`
}

func (s *Service) siteTrafficRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/traffic", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			SiteIDs []string `json:"site_ids"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if len(in.SiteIDs) > 200 {
			respond(w, 400, map[string]string{"error": "站点数量超出统计上限"})
			return
		}
		for _, id := range in.SiteIDs {
			if !core.ValidID(id) {
				respond(w, 400, map[string]string{"error": "站点标识无效"})
				return
			}
		}
		out, err := summarizeSiteTraffic("/var/log/nginx", in.SiteIDs, time.Now())
		if err != nil {
			respond(w, 500, map[string]string{"error": "读取站点访问日志失败"})
			return
		}
		respond(w, 200, out)
	})
}

func summarizeSiteTraffic(base string, ids []string, now time.Time) (core.SiteTrafficSummary, error) {
	result := core.SiteTrafficSummary{Days: []core.SiteTrafficDay{}, Sites: []core.SiteTrafficSite{}, UpdatedAt: now.UTC().Format(time.RFC3339)}
	start := now.In(trafficZone).AddDate(0, 0, -6)
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, trafficZone)
	today := now.In(trafficZone).Format("2006-01-02")
	byDate := map[string]*core.SiteTrafficDay{}
	for offset := 0; offset < 7; offset++ {
		date := start.AddDate(0, 0, offset).Format("2006-01-02")
		result.Days = append(result.Days, core.SiteTrafficDay{Date: date})
		byDate[date] = &result.Days[len(result.Days)-1]
	}
	root, err := os.OpenRoot(base)
	if errors.Is(err, os.ErrNotExist) {
		for _, id := range ids {
			result.Sites = append(result.Sites, core.SiteTrafficSite{ID: id})
		}
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return result, err
	}
	entries, err := dir.ReadDir(10001)
	dir.Close()
	if err != nil {
		return result, err
	}
	if len(entries) == 10001 {
		result.Partial = true
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var scannedBytes int64
	for _, id := range ids {
		if !core.ValidID(id) {
			return result, errors.New("站点标识无效")
		}
		site := core.SiteTrafficSite{ID: id}
		pattern := regexp.MustCompile(`^panel-` + regexp.QuoteMeta(id) + `\.access\.log(?:\.[0-9]{8}-[0-9]{6}(?:\.gz)?)?$`)
		for _, name := range names {
			if !pattern.MatchString(name) {
				continue
			}
			info, statErr := root.Lstat(name)
			if statErr != nil || privateLogEntry(info) != nil {
				return result, errors.New("站点日志文件类型无效")
			}
			budget := min(info.Size(), maxTrafficLogBytes)
			if scannedBytes+budget > maxTrafficRequestBytes {
				result.Partial = true
				continue
			}
			scannedBytes += budget
			file, openErr := root.Open(name)
			if openErr != nil {
				return result, openErr
			}
			if name != "panel-"+id+".access.log" && info.ModTime().Before(start) {
				file.Close()
				continue
			}
			var input io.Reader = file
			var gz *gzip.Reader
			var decompressed *io.LimitedReader
			if strings.HasSuffix(name, ".gz") {
				if info.Size() > maxTrafficLogBytes {
					result.Partial = true
					file.Close()
					continue
				}
				gzReader, gzErr := gzip.NewReader(file)
				if gzErr != nil {
					file.Close()
					return result, gzErr
				}
				gz = gzReader
				decompressed = &io.LimitedReader{R: gz, N: maxTrafficLogBytes}
				input = decompressed
			} else if info.Size() > maxTrafficLogBytes {
				result.Partial = true
				if _, seekErr := file.Seek(info.Size()-maxTrafficLogBytes, io.SeekStart); seekErr != nil {
					file.Close()
					return result, seekErr
				}
				reader := bufio.NewReader(file)
				_, _ = reader.ReadString('\n')
				input = io.LimitReader(reader, maxTrafficLogBytes)
			}
			scanner := bufio.NewScanner(input)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				var line trafficLine
				if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Bytes < 0 {
					continue
				}
				stamp, parseErr := time.Parse(time.RFC3339, line.Time)
				if parseErr != nil || stamp.After(now.Add(time.Minute)) {
					continue
				}
				day := stamp.In(trafficZone).Format("2006-01-02")
				if aggregate := byDate[day]; aggregate != nil {
					aggregate.Bytes += line.Bytes
					aggregate.Requests++
					if day == today {
						site.TodayBytes += line.Bytes
					}
				}
			}
			if scanErr := scanner.Err(); scanErr != nil {
				if gz != nil {
					gz.Close()
				}
				file.Close()
				return result, scanErr
			}
			if decompressed != nil && decompressed.N == 0 {
				result.Partial = true
			}
			if gz != nil {
				gz.Close()
			}
			file.Close()
		}
		result.Sites = append(result.Sites, site)
	}
	return result, nil
}
