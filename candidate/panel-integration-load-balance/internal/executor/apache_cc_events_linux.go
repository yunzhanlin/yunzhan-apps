//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"syscall"
	"time"

	"local/panel/internal/core"
)

func readApacheCCEventsAt(path string, uid, gid int) (core.WAFEventsPage, bool, error) {
	page := core.WAFEventsPage{Events: []core.WAFEvent{}}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return page, false, nil
	}
	if err != nil {
		return page, false, err
	}
	defer f.Close()
	before, err := apacheCCLogFileIdentity(f, uid, gid)
	if err != nil {
		return page, true, err
	}
	page.MetadataBestEffort = true
	page.CCLogCapacityNearLimit = before.Size() >= apacheCCLogMaxBytes-4096
	start := max(int64(0), before.Size()-(4<<20))
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return page, true, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return page, true, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	if start > 0 {
		page.HasMore = true
		lines = lines[1:]
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		page.HasMore = true
		page.CCLogTailIncomplete = true
	}
	known := map[string]bool{}
	for _, key := range []string{"epoch", "epoch_us", "status", "site_id", "site", "ip", "peer", "method", "path", "path_truncated", "reason", "action"} {
		known[key] = true
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		if apacheBodyValidateJSON(line, 4096, 512, 4, known) != nil {
			page.HasMore = true
			continue
		}
		var event struct {
			Epoch   int64 `json:"epoch"`
			EpochUS int64 `json:"epoch_us"`
			core.WAFEvent
		}
		if json.Unmarshal(line, &event) != nil || event.Epoch <= 0 || event.Epoch > 253402300799 || event.EpochUS/1000000 != event.Epoch || !core.ValidID(event.SiteID) || !core.ValidDomain(event.Site) || event.Status < 100 || event.Status > 599 || len(event.Path) > 1536 || len(event.Method) > 32 || event.Action != "block" && event.Action != "observe" || event.Reason != "cc" && event.Reason != "cc-capacity" && event.Reason != "cc-unavailable" {
			page.HasMore = true
			continue
		}
		ip, e1 := netip.ParseAddr(event.IP)
		peer, e2 := netip.ParseAddr(event.Peer)
		if e1 != nil || e2 != nil || ip.Zone() != "" || peer.Zone() != "" {
			page.HasMore = true
			continue
		}
		event.IP, event.Peer = ip.Unmap().String(), peer.Unmap().String()
		event.Time = time.UnixMicro(event.EpochUS).UTC().Format(time.RFC3339Nano)
		if event.Reason == "cc" {
			if event.Action == "block" && event.Status == 429 {
				event.Rate = "REJECTED"
			} else if event.Action == "observe" {
				event.Rate = "REJECTED_DRY_RUN"
			}
		}
		page.Events = append(page.Events, event.WAFEvent)
		if len(page.Events) == 5000 {
			page.HasMore = true
			break
		}
	}
	after, err := f.Stat()
	if err != nil {
		return page, true, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, current) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		page.HasMore = true
	}
	return page, true, nil
}

func (s *Service) readApacheWAFEvents() (core.WAFEventsPage, error) {
	legacy, err := s.readApacheWAFLegacyEvents()
	if err != nil {
		return legacy, err
	}
	path := s.systemPath(apacheCCLogPath)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
			return legacy, nil
		}
		record, readErr := s.moduleInstalledRecord("apache-waf")
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return legacy, readErr
		}
		version, _ := record["version"].(string)
		if readErr == nil && core.ApacheWAFCCVersion(version) {
			settings, ok := record["settings"].(map[string]any)
			if !ok {
				return legacy, errors.New("Apache CC 原策略缺失，未显示为零事件")
			}
			cfg, decodeErr := core.DecodeApacheWAFVersionConfig(settings, version)
			if decodeErr != nil {
				return legacy, decodeErr
			}
			if apacheCCPolicyMayLog(cfg) {
				return legacy, errors.New("Apache CC 日志缺失，保留状态且未显示为零事件")
			}
		}
		return legacy, nil
	} else if err != nil {
		return legacy, err
	}
	// The real reader has a fixed root-owned parent and www-data file. A
	// caller-selected path or test SystemRoot cannot authorize this surface.
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || os.Geteuid() != 0 {
		return legacy, errors.New("Apache CC 日志只允许读取真实受管命名空间")
	}
	if err := apacheBodyOwnedAncestors(apacheCCLogDirectory); err != nil {
		return legacy, err
	}
	uid, gid, err := apacheBodyWorkerAccount()
	if err != nil {
		return legacy, err
	}
	cc, exists, err := readApacheCCEventsAt(path, uid, gid)
	if err != nil {
		return legacy, err
	}
	if !exists {
		return legacy, errors.New("Apache CC 日志在读取期间消失，未显示为零事件")
	}
	legacy.Events = append(legacy.Events, cc.Events...)
	legacy.HasMore = legacy.HasMore || cc.HasMore
	legacy.MetadataBestEffort, legacy.CCLogCapacityNearLimit = cc.MetadataBestEffort, cc.CCLogCapacityNearLimit
	legacy.CCLogTailIncomplete = cc.CCLogTailIncomplete
	sort.SliceStable(legacy.Events, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, legacy.Events[i].Time)
		b, _ := time.Parse(time.RFC3339Nano, legacy.Events[j].Time)
		return a.After(b)
	})
	if len(legacy.Events) > 5000 {
		legacy.Events = legacy.Events[:5000]
		legacy.HasMore = true
	}
	return legacy, nil
}
