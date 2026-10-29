//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

type countryTaskUnitObservation struct {
	Load, Active, Sub string
	PID               int
}

func parseCountryTaskUnitObservation(raw string) (countryTaskUnitObservation, error) {
	var empty countryTaskUnitObservation
	if len(raw) < 1 || len(raw) > 4096 {
		return empty, errors.New("country task native unit observation size invalid")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || name != "LoadState" && name != "ActiveState" && name != "SubState" && name != "MainPID" {
			return empty, errors.New("country task native unit observation unknown field")
		}
		if _, ok := fields[name]; ok {
			return empty, errors.New("country task native unit observation duplicate field")
		}
		fields[name] = value
	}
	if len(fields) != 4 {
		return empty, errors.New("country task native unit observation incomplete")
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	if err != nil || pid < 0 || strconv.Itoa(pid) != fields["MainPID"] {
		return empty, errors.New("country task native PID not canonical")
	}
	out := countryTaskUnitObservation{fields["LoadState"], fields["ActiveState"], fields["SubState"], pid}
	if out.Load == "not-found" && out.Active == "inactive" && out.Sub == "dead" && out.PID == 0 {
		return out, nil
	}
	if out.Load != "loaded" {
		return empty, errors.New("country task native unit load state unknown")
	}
	switch out.Active {
	case "activating":
		if out.Sub != "start" && out.Sub != "start-pre" {
			return empty, errors.New("country task native start phase unknown")
		}
	case "active":
		if out.Sub != "running" || out.PID < 2 {
			return empty, errors.New("country task native running phase unknown")
		}
	case "inactive":
		if out.PID != 0 || out.Sub != "dead" {
			return empty, errors.New("country task native inactive phase unknown")
		}
	case "failed":
		if out.PID != 0 || out.Sub != "failed" {
			return empty, errors.New("country task native failed phase unknown")
		}
	case "deactivating":
		if out.Sub != "stop-sigterm" && out.Sub != "stop-sigkill" && out.Sub != "stop" {
			return empty, errors.New("country task native stop phase unknown")
		}
	default:
		return empty, errors.New("country task native activity state unknown")
	}
	return out, nil
}

func countryTaskLiveProcess(ctx context.Context, marker countryTaskStarted) error {
	if ctx == nil || ctx.Err() != nil || marker.PID < 2 || !countryTaskStartTicksValid(marker.StartTicks) || !wafLogDigestValid(marker.ExecutableSHA) {
		return errors.New("country task current worker identity invalid")
	}
	boot, err := countryTaskBootID()
	if err != nil || boot != marker.BootID {
		return errors.New("country task original worker belongs to another boot")
	}
	readTicks := func() (string, error) {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(marker.PID) + "/stat")
		if err != nil || len(raw) > 8192 {
			return "", errors.New("country task original kernel process unavailable")
		}
		end := strings.LastIndex(string(raw), ") ")
		if end < 1 {
			return "", errors.New("country task original kernel process malformed")
		}
		fields := strings.Fields(string(raw)[end+2:])
		if len(fields) < 20 || !countryTaskStartTicksValid(fields[19]) {
			return "", errors.New("country task original kernel ticks unknown")
		}
		return fields[19], nil
	}
	before, err := readTicks()
	if err != nil || before != marker.StartTicks {
		return errors.New("country task original process lifetime changed")
	}
	f, err := os.Open("/proc/" + strconv.Itoa(marker.PID) + "/exe")
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 {
		return errors.New("country task original executable size unknown")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (256<<20)+1))
	if err != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != marker.ExecutableSHA {
		return errors.New("country task original executable identity changed")
	}
	after, err := readTicks()
	if err != nil || after != before || ctx.Err() != nil {
		return errors.New("country task process changed during observation")
	}
	return nil
}

func (s *Service) wafCountryTaskStatus(ctx context.Context, id string) (core.WAFCountryDataOperation, error) {
	var empty core.WAFCountryDataOperation
	if ctx == nil || ctx.Err() != nil || !core.ValidID(id) {
		return empty, errors.New("国家数据原任务查询身份无效")
	}
	store := productionCountryTaskStore()
	base, err := store.open(false)
	if err != nil {
		return empty, err
	}
	defer base.Close()
	request, _, dir, err := store.read(base, id)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	out := countryTaskOperation(request, "queued", "")
	if raw, err := geoStoreRead(dir.Root, "result.json", 32<<10); err == nil {
		var result core.WAFCountryDataOperation
		if countryCacheDecode(raw, &result) != nil {
			return empty, errors.New("国家数据原终态回执不是完整原始记录")
		}
		parsed, err := core.DecodeWAFCountryDataOperation(raw, id, request.ActorID, request.Selection)
		if err != nil || parsed.RequestSHA != countryTaskRequestDigest(request) || parsed.State != "succeeded" && parsed.State != "failed" && parsed.State != "needs_attention" {
			return empty, errors.New("国家数据原终态与封存请求不同")
		}
		started, err := countryTaskReadStarted(dir.Root, request)
		if err != nil {
			return empty, err
		}
		dispatch, err := countryTaskReadDispatch(dir.Root, request)
		if err != nil || dispatch.BootID != started.BootID {
			return empty, errors.New("国家数据终态的原启动链不能核对")
		}
		return parsed, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	dispatch, err := countryTaskReadDispatch(dir.Root, request)
	if errors.Is(err, os.ErrNotExist) {
		out.State = "needs_attention"
		out.Error = "原请求已封存但没有唯一派发回执，未自动启动或重发"
		return out, nil
	}
	if err != nil {
		return empty, err
	}
	boot, err := countryTaskBootID()
	if err != nil {
		return empty, err
	}
	if dispatch.BootID != boot {
		out.State = "needs_attention"
		out.Error = "原任务属于上次启动且没有终态，保留原记录，未跨重启重放"
		return out, nil
	}
	raw, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--all", "panel-waf-country@"+id+".service", "--property=LoadState,ActiveState,SubState,MainPID")
	if err != nil {
		return empty, err
	}
	unit, err := parseCountryTaskUnitObservation(raw)
	if err != nil {
		return empty, err
	}
	marker, err := countryTaskReadStarted(dir.Root, request)
	if errors.Is(err, os.ErrNotExist) {
		if unit.Load == "loaded" && unit.Active == "activating" {
			return out, nil
		}
		out.State = "needs_attention"
		out.Error = "唯一派发已记录但原工作进程没有完整启动回执，未再次启动"
		return out, nil
	}
	if err != nil {
		return empty, err
	}
	if unit.Load == "loaded" && (unit.Active == "activating" || unit.Active == "active") && unit.PID == marker.PID {
		if err := countryTaskLiveProcess(ctx, marker); err != nil {
			return empty, err
		}
		out.State = "running"
		return out, nil
	}
	out.State = "needs_attention"
	out.Error = "原工作进程已结束或停止但没有完整终态，只核对原ID，不重放下载"
	return out, nil
}
