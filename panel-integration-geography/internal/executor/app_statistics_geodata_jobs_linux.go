//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
	"local/panel/internal/upgradeguard"
)

const statisticsGeoJobsRoot = "/var/lib/panel-executor/statistics-geodata-jobs"

type statisticsGeoRequest struct {
	Format      int                         `json:"format"`
	JobID       string                      `json:"job_id"`
	Selection   core.StatisticsGeoSelection `json:"selection"`
	EnvelopeSHA string                      `json:"envelope_sha256"`
}

func statisticsGeoJobsOpen(create bool) (*statisticsGeoDirectory, error) {
	return (statisticsGeoStore{base: statisticsGeoJobsRoot, trust: appcatalog.Default(), now: time.Now}).open(create)
}
func statisticsGeoJobContents(root *os.Root, published bool) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(6)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 5 {
		return errors.New("地域任务文件集合或数量异常")
	}
	limits := map[string]int64{"request.json": 4096, "envelope.json": appcatalog.MaxGeoDataEnvelopeBytes, "started.json": 4096, "result.json": 32 << 10, "install.lock": 0}
	seen := map[string]bool{}
	for _, entry := range entries {
		limit, ok := limits[entry.Name()]
		if !ok || !published && entry.Name() != "request.json" && entry.Name() != "envelope.json" {
			return errors.New("地域任务含未知阶段成员")
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !moduleRecordInfo(info, false, false) || info.Size() > limit || entry.Name() != "install.lock" && info.Size() < 1 {
			return errors.New("地域任务文件身份或预算异常")
		}
		seen[entry.Name()] = true
	}
	if published && (!seen["request.json"] || !seen["envelope.json"]) {
		return errors.New("地域任务缺少原始交付")
	}
	return nil
}
func readStatisticsGeoJob(id string) (statisticsGeoRequest, []byte, *statisticsGeoDirectory, *os.Root, error) {
	var request statisticsGeoRequest
	if !core.ValidID(id) {
		return request, nil, nil, nil, errors.New("地域任务标识无效")
	}
	base, err := statisticsGeoJobsOpen(false)
	if err != nil {
		return request, nil, nil, nil, err
	}
	fail := func(err error) (statisticsGeoRequest, []byte, *statisticsGeoDirectory, *os.Root, error) {
		base.Close()
		return request, nil, nil, nil, err
	}
	info, err := base.Lstat(id)
	if err != nil || !moduleRecordInfo(info, true, false) {
		return fail(errors.New("地域任务目录身份异常"))
	}
	root, err := base.OpenRoot(id)
	if err != nil {
		return fail(err)
	}
	bad := func(err error) (statisticsGeoRequest, []byte, *statisticsGeoDirectory, *os.Root, error) {
		root.Close()
		return fail(err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !base.current() {
		return bad(errors.New("地域任务目录打开期间变化"))
	}
	if err = statisticsGeoJobContents(root, true); err != nil {
		return bad(err)
	}
	raw, err := geoStoreRead(root, "request.json", 4096)
	if err != nil || decodeStatisticsGeoPrivate(raw, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateStatisticsGeoSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return bad(errors.New("地域任务原始请求损坏"))
	}
	envelope, err := geoStoreRead(root, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return bad(errors.New("地域任务原始签名材料损坏"))
	}
	return request, envelope, base, root, nil
}
func (s *Service) statisticsGeoGuard(selection core.StatisticsGeoSelection) error {
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	id, err := s.statisticsGeoInstance()
	if err != nil || id != selection.InstallationID {
		return errors.New("统计应用实例已改变，未选择新地域库")
	}
	return nil
}
func (s *Service) verifyStatisticsGeoJob(in core.StatisticsGeoSelection, raw []byte) (statisticsGeoStore, error) {
	if core.ValidateStatisticsGeoSelection(in) != nil || s.statisticsGeoGuard(in) != nil {
		return statisticsGeoStore{}, errors.New("统计地域任务与当前安装实例不符")
	}
	store, err := s.statisticsGeoDataStore()
	if err != nil {
		return store, err
	}
	store.guard = func() error { return s.statisticsGeoGuard(in) }
	if in.Action == "install" {
		envelope, err := appcatalog.DecodeGeoDataEnvelope(raw)
		if err != nil {
			return store, err
		}
		a, err := store.trust.VerifyGeoDataEnvelope(envelope, in.AppVersion, in.AppManifestSHA, time.Now(), nil)
		if err != nil || a.Data().Manifest().Release != in.Release || a.Data().SHA256() != in.DataManifestSHA {
			return store, errors.New("地域交付与任务双签名绑定不同")
		}
	} else {
		if !bytes.Equal(raw, []byte("{}")) {
			return store, errors.New("回滚不能混入新交付")
		}
		root, err := store.open(false)
		if err != nil {
			return store, err
		}
		defer root.Close()
		name := geodata.Channel + "-" + in.Release + "-" + in.DataManifestSHA
		a, err := store.authority(root.Root, name)
		if err != nil || a.AppVersion() != in.AppVersion || a.AppSHA256() != in.AppManifestSHA {
			return store, errors.New("回滚副本不能独立核对")
		}
	}
	return store, nil
}
func (s *Service) createStatisticsGeoJob(id string, in core.StatisticsGeoSelection, raw []byte) error {
	if !core.ValidID(id) {
		return errors.New("地域任务ID无效")
	}
	store, err := s.verifyStatisticsGeoJob(in, raw)
	if err != nil {
		return err
	}
	// Prepare exact private leaves before the hardened unit starts. No data
	// selection, download, app installation or service enable happens here.
	data, err := store.open(true)
	if err != nil {
		return err
	}
	data.Close()
	lease, err := statisticsGeoInstanceLease(false)
	if err != nil {
		return err
	}
	defer lease.Close()
	base, err := statisticsGeoJobsOpen(true)
	if err != nil {
		return err
	}
	defer base.Close()
	if _, err = base.Lstat(id); err == nil {
		prior, _, p, r, err := readStatisticsGeoJob(id)
		if err != nil {
			return err
		}
		r.Close()
		p.Close()
		if prior.Selection != in {
			return errors.New("地域任务ID已绑定其他请求")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := base.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(129)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) >= 128 {
		return errors.New("地域任务达到128份，原证据保留")
	}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name(), ".request-")
		info, e := base.Lstat(entry.Name())
		if !core.ValidID(name) || e != nil || !moduleRecordInfo(info, true, false) {
			return errors.New("地域任务目录有未知或不受信条目")
		}
	}
	stage := ".request-" + core.ID()
	if err = base.Mkdir(stage, 0700); err != nil {
		return err
	}
	child, err := base.OpenRoot(stage)
	if err != nil {
		return err
	}
	defer child.Close()
	request := statisticsGeoRequest{1, id, in, core.Hash(string(raw))}
	requestRaw, _ := json.Marshal(request)
	if err = ruleFeedStoreWrite(child, "request.json", requestRaw, 0600); err != nil {
		return err
	}
	if err = ruleFeedStoreWrite(child, "envelope.json", raw, 0600); err != nil {
		return err
	}
	if err = ruleFeedStoreSync(child); err != nil {
		return err
	}
	if !base.current() {
		return errors.New("地域请求发布前目录变化")
	}
	f, err := base.Open(".")
	if err != nil {
		return err
	}
	err = unix.Renameat2(int(f.Fd()), stage, int(f.Fd()), id, unix.RENAME_NOREPLACE)
	f.Close()
	if err != nil {
		return err
	}
	return ruleFeedStoreSync(base.Root)
}
func (s *Service) statisticsGeoJobStatus(ctx context.Context, id string) (core.StatisticsGeoOperation, error) {
	request, _, base, root, err := readStatisticsGeoJob(id)
	if err != nil {
		return core.StatisticsGeoOperation{}, err
	}
	defer root.Close()
	defer base.Close()
	out := core.StatisticsGeoOperation{JobID: id, Selection: request.Selection, State: "queued", Steps: []core.Step{}}
	raw, err := geoStoreRead(root, "result.json", 32<<10)
	if err == nil {
		var result core.StatisticsGeoOperation
		if decodeStatisticsGeoPrivate(raw, &result) != nil || result.JobID != id || result.Selection != request.Selection || len(result.Steps) > 16 || len(result.Error) > 1024 || result.State != "succeeded" && result.State != "failed" || result.State == "succeeded" && result.Error != "" || result.State == "failed" && result.Error == "" {
			return out, errors.New("地域终态回执损坏")
		}
		started, err := geoStoreRead(root, "started.json", 4096)
		var marker statisticsGeoRequest
		if err != nil || decodeStatisticsGeoPrivate(started, &marker) != nil || marker != request {
			return out, errors.New("地域终态缺少匹配的原始启动回执")
		}
		return result, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	state, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--all", "panel-statistics-geodata@"+id+".service", "--property=LoadState,ActiveState,MainPID,ExecMainStartTimestampMonotonic")
	if err != nil {
		return out, err
	}
	out.State, out.Error, err = threatIDSRuleFeedUnitState(state)
	if err != nil {
		return out, err
	}
	started, err := geoStoreRead(root, "started.json", 4096)
	if err == nil {
		var marker statisticsGeoRequest
		if decodeStatisticsGeoPrivate(started, &marker) != nil || marker != request {
			return out, errors.New("地域启动标记绑定不同")
		}
		if out.State == "queued" {
			out.State = "needs-attention"
			out.Error = "原地域任务曾启动但无完整结果，不自动重发"
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	return out, nil
}
func (s *Service) statisticsGeoJobRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/statistics/geodata", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.statisticsGeoState()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/statistics/geodata/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.statisticsGeoJobStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/statistics/geodata/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		in, err := core.ParseStatisticsGeoSelectionQuery(r.URL.Query())
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, appcatalog.MaxGeoDataEnvelopeBytes))
		if err != nil {
			respond(w, 400, map[string]string{"error": "地域交付超限"})
			return
		}
		if in.Action == "rollback" {
			if !bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
				respond(w, 400, map[string]string{"error": "回滚不能混入新交付或未知字段"})
				return
			}
			raw = []byte("{}")
		} else {
			envelope, err := appcatalog.DecodeGeoDataEnvelope(raw)
			if err != nil {
				respond(w, 400, map[string]string{"error": err.Error()})
				return
			}
			raw, err = json.Marshal(envelope)
			if err != nil {
				respond(w, 400, map[string]string{"error": "地域交付编码失败"})
				return
			}
		}
		id := r.PathValue("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		if err = s.createStatisticsGeoJob(id, in, raw); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		out, err := s.statisticsGeoJobStatus(r.Context(), id)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if out.State == "queued" {
			if _, err = s.moduleCommand(r.Context(), 5*time.Second, "/usr/bin/systemctl", "start", "--no-block", "panel-statistics-geodata@"+id+".service"); err != nil {
				respond(w, 409, map[string]string{"error": "地域任务派发未确认，保留原请求"})
				return
			}
		}
		respond(w, 202, out)
	})
}

func RunStatisticsGeoJob(id string) error {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("地域固定入口身份无效")
	}
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	s := New(Config{})
	request, raw, base, root, err := readStatisticsGeoJob(id)
	if err != nil {
		return err
	}
	defer base.Close()
	defer root.Close()
	lock, err := root.OpenFile("install.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if errors.Is(err, os.ErrExist) {
		lock, err = root.OpenFile("install.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 {
		return errors.New("地域任务锁身份异常")
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("原地域任务仍在执行")
	}
	if _, err = root.Lstat("result.json"); err == nil {
		return errors.New("地域原任务已有终态，不覆盖或重复执行")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err = root.Lstat("started.json"); err == nil {
		return errors.New("地域原任务曾执行但无终态，不自动重放")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lease, err := statisticsGeoInstanceLease(false)
	if err != nil {
		return err
	}
	defer lease.Close()
	started, _ := json.Marshal(request)
	if err = ruleFeedStoreWrite(root, "started.json", started, 0600); err != nil {
		return err
	}
	if err = ruleFeedStoreSync(root); err != nil {
		return err
	}
	out := core.StatisticsGeoOperation{JobID: id, Selection: request.Selection, State: "failed", Steps: []core.Step{}}
	apply := func() error {
		store, err := s.verifyStatisticsGeoJob(request.Selection, raw)
		if err != nil {
			return err
		}
		var snapshot interface{ Close() error }
		if request.Selection.Action == "install" {
			envelope, err := appcatalog.DecodeGeoDataEnvelope(raw)
			if err != nil {
				return err
			}
			_, value, err := store.install(ctx, envelope, request.Selection.AppManifestSHA)
			if err != nil {
				return err
			}
			snapshot = value
		} else {
			name := geodata.Channel + "-" + request.Selection.Release + "-" + request.Selection.DataManifestSHA
			value, err := store.rollback(ctx, name)
			if err != nil {
				return err
			}
			snapshot = value
		}
		if snapshot != nil {
			snapshot.Close()
		}
		out.State = "succeeded"
		out.Steps = append(out.Steps, core.Step{Time: core.Now(), Message: "原始应用与数据签名、安装实例和完整城市库已核对，数据选择已持久提交；不安装/卸载应用或修改网站"})
		return nil
	}
	err = apply()
	if err != nil {
		out.Error = err.Error()
		if len(out.Error) > 1024 {
			out.Error = out.Error[:1024]
		}
	}
	result, _ := json.Marshal(out)
	if writeErr := ruleFeedStoreWrite(root, "result.json", result, 0600); writeErr != nil {
		return errors.New("地域业务可能执行但终态保存失败，请核对原任务")
	}
	if syncErr := ruleFeedStoreSync(root); syncErr != nil {
		return syncErr
	}
	return err
}
