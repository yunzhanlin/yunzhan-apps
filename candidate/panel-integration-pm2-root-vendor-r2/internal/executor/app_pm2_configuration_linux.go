//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// An intent is immutable and synced before the live manifest changes. A
// separate immutable receipt distinguishes a durable commit from a lost HTTP
// reply. Neither record contains plaintext environment values.
const pm2ConfigRecordLimit = 128 << 10
const pm2ConfigIntentLimit = 512

var moduleBootID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type pm2ConfigIntent struct {
	Format      int               `json:"format"`
	ID          string            `json:"id"`
	AppID       string            `json:"app_id"`
	SiteID      string            `json:"site_id"`
	CreatedAt   string            `json:"created_at"`
	BootID      string            `json:"boot_id"`
	Owner       *moduleApplyOwner `json:"owner"`
	RequestSHA  string            `json:"request_sha256"`
	Before      []byte            `json:"before"`
	After       []byte            `json:"after"`
	BeforeSHA   string            `json:"before_sha256"`
	AfterSHA    string            `json:"after_sha256"`
	BeforeState pm2UnitState      `json:"before_state"`
}
type pm2ConfigReceipt struct {
	Format      int    `json:"format"`
	ID          string `json:"id"`
	IntentSHA   string `json:"intent_sha256"`
	State       string `json:"state"`
	ManifestSHA string `json:"manifest_sha256"`
	FinishedAt  string `json:"finished_at"`
}
type pm2ConfigRecord struct {
	Intent       pm2ConfigIntent
	Receipt      *pm2ConfigReceipt
	Cancellation *pm2ConfigCancellation
	SHA          string
	Raw          []byte
}
type pm2ConfigCancellation struct {
	Format                     int    `json:"format"`
	ID                         string `json:"id"`
	AppID                      string `json:"app_id"`
	CreatedAt                  string `json:"created_at"`
	CancelledBeforePublication bool   `json:"cancelled_before_publication"`
}
type pm2ConfigStore struct {
	*modulePrivateDirectory
}

func pm2ConfigHash(raw []byte) string { return core.Hash(string(raw)) }

// Child handles remain attached to the same trusted configured namespace.
func pm2ConfigChild(d *modulePrivateDirectory, name string, create bool) error {
	info, err := d.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && create {
		if !d.current() {
			return errors.New("PM2 transaction parent changed")
		}
		if err = d.Mkdir(name, 0700); err != nil {
			return err
		}
		if err = pm2ConfigSync(d); err != nil {
			return err
		}
		info, err = d.Lstat(name)
	}
	if err != nil {
		return err
	}
	if !moduleRecordInfo(info, true, false) {
		return errors.New("PM2 transaction directory is not private")
	}
	child, err := d.OpenRoot(name)
	if err != nil {
		return err
	}
	opened, e := child.Stat(".")
	if e != nil || !programQueueSame(info, opened) {
		child.Close()
		return errors.New("PM2 transaction directory changed")
	}
	d.roots = append(d.roots, child)
	d.paths = append(d.paths, filepath.Join(d.paths[len(d.paths)-1], name))
	d.Root = child
	if !d.current() {
		return errors.New("PM2 transaction parent changed")
	}
	return nil
}
func (s *Service) openPM2ConfigStore(create bool) (*pm2ConfigStore, error) {
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	if err = pm2ConfigChild(d, "configuration-transactions", create); err != nil {
		d.Close()
		return nil, err
	}
	return &pm2ConfigStore{d}, nil
}
func pm2ConfigRead(d *modulePrivateDirectory, name string) ([]byte, error) {
	return pm2ConfigReadRoot(d.Root, name, d.current)
}
func pm2ConfigReadRoot(root *os.Root, name string, current func() bool) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > pm2ConfigRecordLimit {
		return nil, errors.New("PM2 private record identity or capacity is invalid")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return pm2ConfigReadDurable(f, info, func() bool {
		visible, err := root.Lstat(name)
		return err == nil && programQueueSame(info, visible) && current()
	})
}
func pm2ConfigSync(d *modulePrivateDirectory) error {
	return pm2ConfigSyncRoot(d.Root, d.current)
}
func pm2ConfigSyncRoot(root *os.Root, current func() bool) error {
	if !current() {
		return errors.New("PM2 transaction namespace changed")
	}
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return pm2ConfigSyncDurable(f, current)
}

// Never replace an original intent/result, including a partial file left by
// interrupted storage. An unverifiable file blocks further mutation.
func pm2ConfigCreate(d *modulePrivateDirectory, name string, raw []byte) error {
	if len(raw) < 1 || len(raw) > pm2ConfigRecordLimit || !d.current() {
		return errors.New("PM2 transaction cannot be durably published")
	}
	f, err := d.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if err = pm2ConfigWriteDurable(f, raw); err != nil {
		return err
	}
	return pm2ConfigSync(d)
}
func pm2ConfigApp(raw []byte) (pm2App, error) {
	var app pm2App
	if len(raw) == 0 || len(raw) > 64<<10 || decodeProgramQueueJSON(raw, &app) != nil || !moduleResourceID.MatchString(app.ID) || !core.ValidID(app.SiteID) || !core.ValidFilePath(app.Entry, false) || !strings.HasSuffix(app.Entry, ".js") || app.Port < 1024 || app.Port > 65535 || app.Revision < 1 || len(app.EnvironmentKeys) > 64 {
		return app, errors.New("PM2 encrypted manifest cannot be verified")
	}
	if _, _, err := pm2Limits(app.Instances, app.MemoryMB); err != nil {
		return app, err
	}
	return app, nil
}
func validatePM2ConfigIntent(in pm2ConfigIntent) error {
	before, e := pm2ConfigApp(in.Before)
	after, e2 := pm2ConfigApp(in.After)
	_, atErr := time.Parse(time.RFC3339, in.CreatedAt)
	if e != nil || e2 != nil || in.Format != 1 || !core.ValidID(in.ID) || !moduleResourceID.MatchString(in.AppID) || !core.ValidID(in.SiteID) || atErr != nil || !moduleBootID.MatchString(in.BootID) || in.Owner == nil || in.Owner.PID <= 1 || in.Owner.StartTime == 0 || !coreSHA.MatchString(in.RequestSHA) || in.BeforeSHA != pm2ConfigHash(in.Before) || in.AfterSHA != pm2ConfigHash(in.After) || before.ID != in.AppID || after.ID != in.AppID || before.SiteID != in.SiteID || after.SiteID != in.SiteID || before.CreatedAt != after.CreatedAt || before.Revision == int64(^uint64(0)>>1) || after.Revision != before.Revision+1 {
		return errors.New("PM2 configuration intent binding cannot be verified")
	}
	st := in.BeforeState
	if st.LoadState != "loaded" || (st.UnitFileState != "enabled" && st.UnitFileState != "disabled" && st.UnitFileState != "enabled-runtime") || (st.ActiveState != "active" && st.ActiveState != "inactive") {
		return errors.New("PM2 configuration intent service state cannot be verified")
	}
	return nil
}
func validatePM2ConfigReceipt(r pm2ConfigReceipt, record pm2ConfigRecord) error {
	_, err := time.Parse(time.RFC3339, r.FinishedAt)
	expected := record.Intent.BeforeSHA
	if r.State == "committed" {
		expected = record.Intent.AfterSHA
	} else if r.State != "rolled_back" && r.State != "recovered_stopped" {
		return errors.New("PM2 transaction receipt state is unknown")
	}
	if r.Format != 1 || r.ID != record.Intent.ID || r.IntentSHA != record.SHA || r.ManifestSHA != expected || err != nil {
		return errors.New("PM2 transaction receipt binding cannot be verified")
	}
	return nil
}
func (d *pm2ConfigStore) records() (map[string]pm2ConfigRecord, error) {
	before, err := d.Stat(".")
	if err != nil {
		return nil, err
	}
	f, err := d.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(2*pm2ConfigIntentLimit + 1)
	if closeErr := f.Close(); closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2*pm2ConfigIntentLimit {
		return nil, errors.New("PM2 complete configuration inventory exceeds its 512-intent budget")
	}
	files := map[string][]byte{}
	total := 0
	for _, entry := range entries {
		raw, e := pm2ConfigRead(d.modulePrivateDirectory, entry.Name())
		if e != nil {
			return nil, e
		}
		total += len(raw)
		if total > 64<<20 {
			return nil, errors.New("PM2 configuration streaming budget exceeded")
		}
		files[entry.Name()] = raw
	}
	if err = pm2ConfigSync(d.modulePrivateDirectory); err != nil {
		return nil, err
	}
	after, statErr := d.Stat(".")
	if statErr != nil || !programQueueSame(before, after) || !d.current() {
		return nil, errors.New("PM2 configuration namespace changed")
	}
	return decodePM2ConfigurationRecords(files)
}
func decodePM2ConfigurationRecords(files map[string][]byte) (map[string]pm2ConfigRecord, error) {
	if len(files) > 2*pm2ConfigIntentLimit {
		return nil, errors.New("PM2 configuration complete inventory exceeds budget")
	}
	intents, receipts, cancellations := map[string][]byte{}, map[string][]byte{}, map[string][]byte{}
	var total int
	for name, raw := range files {
		total += len(raw)
		if len(raw) < 1 || len(raw) > pm2ConfigRecordLimit || total > 64<<20 {
			return nil, errors.New("PM2 configuration streaming budget exceeded")
		}
		id, ok := strings.CutSuffix(name, ".intent.json")
		kind := "intent"
		if !ok {
			id, ok = strings.CutSuffix(name, ".result.json")
			kind = "result"
		}
		if !ok {
			id, ok = strings.CutSuffix(name, ".cancel.json")
			kind = "cancel"
		}
		if !ok || !core.ValidID(id) {
			return nil, errors.New("PM2 configuration inventory contains an unknown file")
		}
		if kind == "intent" {
			intents[id] = raw
		} else if kind == "result" {
			receipts[id] = raw
		} else {
			cancellations[id] = raw
		}
	}
	if len(intents) > pm2ConfigIntentLimit {
		return nil, errors.New("PM2 configuration inventory exceeds budget")
	}
	out := map[string]pm2ConfigRecord{}
	for id, raw := range cancellations {
		var cancel pm2ConfigCancellation
		if decodeProgramQueueJSON(raw, &cancel) != nil || cancel.Format != 1 || cancel.ID != id || !moduleResourceID.MatchString(cancel.AppID) || !cancel.CancelledBeforePublication {
			return nil, errors.New("PM2 configuration cancellation binding is invalid")
		}
		if _, err := time.Parse(time.RFC3339, cancel.CreatedAt); err != nil {
			return nil, errors.New("PM2 cancellation timestamp cannot be verified")
		}
		if _, ok := intents[id]; ok {
			return nil, errors.New("PM2 cancellation conflicts with an original intent")
		}
		if _, ok := receipts[id]; ok {
			return nil, errors.New("PM2 cancellation conflicts with an original receipt")
		}
		out[id] = pm2ConfigRecord{Cancellation: &cancel, Raw: raw, SHA: pm2ConfigHash(raw)}
	}
	if len(intents)+len(cancellations) > pm2ConfigIntentLimit {
		return nil, errors.New("PM2 complete configuration request inventory exceeds budget")
	}
	for id, raw := range intents {
		var in pm2ConfigIntent
		if decodeProgramQueueJSON(raw, &in) != nil || in.ID != id || validatePM2ConfigIntent(in) != nil {
			return nil, errors.New("PM2 configuration intent is damaged; original retained")
		}
		record := pm2ConfigRecord{Intent: in, SHA: pm2ConfigHash(raw), Raw: raw}
		if result, ok := receipts[id]; ok {
			var receipt pm2ConfigReceipt
			if decodeProgramQueueJSON(result, &receipt) != nil || validatePM2ConfigReceipt(receipt, record) != nil {
				return nil, errors.New("PM2 configuration receipt is damaged; original retained")
			}
			record.Receipt = &receipt
			delete(receipts, id)
		}
		out[id] = record
	}
	if len(receipts) != 0 {
		return nil, errors.New("PM2 configuration receipt has no original intent or namespace changed")
	}
	return out, nil
}
func (s *Service) pm2ConfigRecords() (map[string]pm2ConfigRecord, error) {
	d, err := s.openPM2ConfigStore(false)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]pm2ConfigRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.records()
}
func publicPM2Config(record pm2ConfigRecord) map[string]any {
	if record.Cancellation != nil {
		c := record.Cancellation
		return map[string]any{"resource_id": c.AppID, "pm2_operation_id": c.ID, "expected_sha": record.SHA, "state": "cancelled_before_publication", "created_at": c.CreatedAt, "automatic_replay": false}
	}
	before, _ := pm2ConfigApp(record.Intent.Before)
	after, _ := pm2ConfigApp(record.Intent.After)
	state := "needs_attention"
	if record.Receipt != nil {
		state = record.Receipt.State
	}
	return map[string]any{"resource_id": record.Intent.AppID, "site_id": record.Intent.SiteID, "pm2_operation_id": record.Intent.ID, "expected_sha": record.SHA, "state": state, "previous_revision": before.Revision, "next_revision": after.Revision, "created_at": record.Intent.CreatedAt, "previous_running": record.Intent.BeforeState.ActiveState == "active", "previous_boot_enabled": record.Intent.BeforeState.UnitFileState == "enabled", "automatic_replay": false}
}
func (s *Service) pm2ConfigurationReport(in core.AppModuleInput) (any, error) {
	records, err := s.pm2ConfigRecords()
	if err != nil {
		return nil, err
	}
	return publicPM2ConfigPage(records, in)
}
func publicPM2ConfigPage(records map[string]pm2ConfigRecord, in core.AppModuleInput) (map[string]any, error) {
	if in.Limit < 0 || in.Limit > 128 || in.Offset < 0 || in.Offset > pm2ConfigIntentLimit {
		return nil, errors.New("PM2 配置事务分页超出范围")
	}
	if in.PM2OperationID != "" && !core.ValidID(in.PM2OperationID) {
		return nil, errors.New("PM2 原配置事务标识无效")
	}
	if in.ResourceID != "" && !moduleResourceID.MatchString(in.ResourceID) {
		return nil, errors.New("PM2 项目标识无效")
	}
	rows := []any{}
	ids := []string{}
	for id, record := range records {
		appID := record.Intent.AppID
		if record.Cancellation != nil {
			appID = record.Cancellation.AppID
		}
		if (in.PM2OperationID == "" || id == in.PM2OperationID) && (in.ResourceID == "" || in.ResourceID == appID) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := records[ids[i]], records[ids[j]]
		x, y := a.Intent.CreatedAt, b.Intent.CreatedAt
		if a.Cancellation != nil {
			x = a.Cancellation.CreatedAt
		}
		if b.Cancellation != nil {
			y = b.Cancellation.CreatedAt
		}
		if x != y {
			return x > y
		}
		return ids[i] > ids[j]
	})
	if in.PM2OperationID != "" && len(ids) != 1 {
		return map[string]any{"configuration_inventory_complete": true, "configuration_transactions": []any{}, "selected_operation_absent": true, "resource_id": in.ResourceID, "pm2_operation_id": in.PM2OperationID, "automatic_replay": false}, nil
	}
	limit := in.Limit
	if limit == 0 {
		limit = 64
	}
	offset := in.Offset
	if offset > len(ids) {
		offset = len(ids)
	}
	end := offset + limit
	if end > len(ids) {
		end = len(ids)
	}
	for _, id := range ids[offset:end] {
		rows = append(rows, publicPM2Config(records[id]))
	}
	return map[string]any{"configuration_transactions": rows, "configuration_inventory_complete": true, "total": len(ids), "offset": offset, "limit": limit, "next_offset": end, "page_complete": end == len(ids), "max_retained_intents": pm2ConfigIntentLimit, "automatic_replay": false}, nil
}

func pm2ConfigPending(records map[string]pm2ConfigRecord, app string) bool {
	for _, r := range records {
		if r.Intent.AppID == app && r.Receipt == nil && r.Cancellation == nil {
			return true
		}
	}
	return false
}
func (s *Service) pm2ConfigLiveBytes(id string) ([]byte, error) {
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = pm2ConfigChild(d, "apps", false); err != nil {
		return nil, err
	}
	return pm2ConfigRead(d, id+".json")
}

// The project lock serializes normal panel writers. The expected exact bytes
// and retained anchored handles also prevent a detached parent or stale caller
// from replacing a different manifest. An interrupted temporary file is kept.
func (s *Service) pm2ConfigPublish(id, operation string, expected, next []byte) error {
	if !moduleResourceID.MatchString(id) || !core.ValidID(operation) {
		return errors.New("PM2 manifest identity is invalid")
	}
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return err
	}
	defer d.Close()
	if err = pm2ConfigChild(d, "apps", false); err != nil {
		return err
	}
	current, err := pm2ConfigRead(d, id+".json")
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("PM2 live configuration changed; no replacement performed")
	}
	temp := "." + operation + "-" + core.ID() + ".configuration"
	if err = pm2ConfigCreate(d, temp, next); err != nil {
		return err
	}
	current, err = pm2ConfigRead(d, id+".json")
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("PM2 live configuration changed before publication")
	}
	dir, err := d.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = unix.Renameat2(int(dir.Fd()), temp, int(dir.Fd()), id+".json", 0); err != nil {
		return err
	}
	return pm2ConfigSync(d)
}
func (d *pm2ConfigStore) finish(record pm2ConfigRecord, state string) error {
	r := pm2ConfigReceipt{Format: 1, ID: record.Intent.ID, IntentSHA: record.SHA, State: state, ManifestSHA: record.Intent.BeforeSHA, FinishedAt: core.Now()}
	if state == "committed" {
		r.ManifestSHA = record.Intent.AfterSHA
	}
	if err := validatePM2ConfigReceipt(r, record); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return pm2ConfigCreate(d.modulePrivateDirectory, r.ID+".result.json", append(raw, '\n'))
}
func currentPM2ConfigBoot() (string, error) {
	raw, err := readModuleProcFile("/proc/sys/kernel/random/boot_id", 128)
	boot := strings.TrimSpace(string(raw))
	if err != nil || !moduleBootID.MatchString(boot) {
		return "", errors.New("PM2 transaction boot identity is unavailable")
	}
	return boot, nil
}

// Called both by ExecCondition and ServePM2. A candidate may start before
// commit only in the original boot while the exact executor owns its lock.
func (s *Service) checkPM2ConfigurationStart(ctx context.Context, id string) error {
	if !moduleResourceID.MatchString(id) {
		return errors.New("PM2 project identity is invalid")
	}
	records, err := s.pm2ConfigRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Intent.AppID != id || record.Receipt != nil {
			continue
		}
		boot, err := currentPM2ConfigBoot()
		if err != nil || boot != record.Intent.BootID {
			return errors.New("PM2 configuration update was interrupted; inspect and recover it first")
		}
		raw, err := s.pm2ConfigLiveBytes(id)
		if err != nil || (pm2ConfigHash(raw) != record.Intent.BeforeSHA && pm2ConfigHash(raw) != record.Intent.AfterSHA) {
			return errors.New("PM2 pending transaction does not match the live manifest")
		}
		if err = s.authorizeModuleCandidate(ctx, filepath.Join(s.moduleDir("pm2-manager"), "locks", id+".lock"), record.Intent.Owner); err != nil {
			return err
		}
	}
	return nil
}
func CheckPM2ConfigurationStart(id string) error {
	if os.Geteuid() != 0 {
		return errors.New("PM2 configuration start check requires root")
	}
	s := New(Config{SitesDir: "/srv/panel/sites"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.checkPM2ConfigurationStart(ctx, id); err != nil {
		return err
	}
	return s.pm2RootVendorReady(ctx)
}
func (s *Service) recoverPM2Configuration(ctx context.Context, in core.AppModuleInput, records map[string]pm2ConfigRecord) (any, error) {
	record, ok := records[in.PM2OperationID]
	if !ok || record.Intent.AppID != in.ResourceID || record.SHA != in.ExpectedSHA || in.Confirm != "RECOVER PM2 "+record.Intent.ID {
		return nil, errors.New("请选择原配置事务并填写精确恢复确认")
	}
	if record.Receipt != nil || record.Cancellation != nil {
		return map[string]any{"configuration_transaction": publicPM2Config(record), "already_terminal": true, "automatic_replay": false}, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	raw, err := s.pm2ConfigLiveBytes(in.ResourceID)
	if err != nil || (!bytes.Equal(raw, record.Intent.Before) && !bytes.Equal(raw, record.Intent.After)) {
		return nil, errors.New("当前配置与原事务不一致，未覆盖或重启")
	}
	unit := "panel-pm2@" + in.ResourceID + ".service"
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "disable", "--now", unit); err != nil {
		return nil, errors.New("候选停止或禁用开机启动未完成，原事务保留")
	}
	state, err := s.readPM2UnitState(ctx, unit)
	if err != nil || state.ActiveState != "inactive" || state.UnitFileState != "disabled" {
		return nil, errors.New("候选未确认停止，未恢复旧配置")
	}
	if err = s.pm2ConfigPublish(in.ResourceID, record.Intent.ID, raw, record.Intent.Before); err != nil {
		return nil, err
	}
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = d.finish(record, "recovered_stopped"); err != nil {
		return nil, errors.New("旧配置已恢复并保持停止，但恢复回执保存失败；请只读核对原事务")
	}
	record.Receipt = &pm2ConfigReceipt{State: "recovered_stopped"}
	return map[string]any{"configuration_transaction": publicPM2Config(record), "service_active": false, "boot_enabled": false, "old_encrypted_configuration_restored": true, "automatic_replay": false}, nil
}

// A caller-supplied nonce supports observing a lost reply. Legacy clients get
// a deterministic identity for the exact old ciphertext and request, so a
// failed rollback cannot turn an automatic retry into another restart.
func pm2ConfigurationIdentity(in core.AppModuleInput, before []byte) (string, string, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return "", "", err
	}
	requestSHA := pm2ConfigHash(raw)
	id := in.PM2OperationID
	if id == "" {
		id = core.Hash("pm2-config-legacy-v1:" + in.ResourceID + ":" + pm2ConfigHash(before) + ":" + requestSHA)[:32]
	}
	if !core.ValidID(id) {
		return "", "", errors.New("PM2 配置操作标识无效")
	}
	return id, requestSHA, nil
}
func pm2ConfigurationDuplicate(in core.AppModuleInput, before []byte, records map[string]pm2ConfigRecord) (any, bool, error) {
	id, requestSHA, err := pm2ConfigurationIdentity(in, before)
	if err != nil {
		return nil, true, err
	}
	record, ok := records[id]
	if !ok {
		return nil, false, nil
	}
	if record.Cancellation != nil {
		return nil, true, errors.New("PM2 原配置请求已持久取消，未执行延迟请求")
	}
	if record.Intent.AppID != in.ResourceID || record.Intent.RequestSHA != requestSHA {
		return nil, true, errors.New("PM2 原配置操作标识已用于不同请求；未重复执行")
	}
	if record.Receipt == nil && record.Cancellation == nil {
		return nil, true, errors.New("PM2 原配置操作尚未确认，请查看配置事务并显式恢复；未重复执行")
	}
	if record.Receipt.State != "committed" {
		return nil, true, errors.New("PM2 原配置操作已回退或恢复停止；保留原失败，未重复执行")
	}
	return map[string]any{"ok": true, "configuration_transaction": publicPM2Config(record), "original_durable_commit": true, "duplicate_observation": true, "automatic_replay": false}, true, nil
}

func (s *Service) cancelPM2ConfigurationRequest(ctx context.Context, in core.AppModuleInput) (any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !moduleResourceID.MatchString(in.ResourceID) || !core.ValidID(in.PM2OperationID) || in.Confirm != "CANCEL PM2 "+in.PM2OperationID {
		return nil, errors.New("请先只读核对原操作，再精确确认取消尚未接受的配置请求")
	}
	d, err := s.openPM2ConfigStore(true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	records, err := d.records()
	if err != nil {
		return nil, err
	}
	if record, exists := records[in.PM2OperationID]; exists {
		row := publicPM2Config(record)
		if row["resource_id"] != in.ResourceID {
			return nil, errors.New("原操作属于其他项目，未取消")
		}
		return map[string]any{"configuration_inventory_complete": true, "configuration_transactions": []any{row}, "request_cancelled": record.Cancellation != nil, "original_operation_retained": true, "automatic_replay": false}, nil
	}
	if len(records) >= pm2ConfigIntentLimit {
		return nil, errors.New("PM2 配置请求记录已达上限，原请求未重发")
	}
	cancel := pm2ConfigCancellation{Format: 1, ID: in.PM2OperationID, AppID: in.ResourceID, CreatedAt: core.Now(), CancelledBeforePublication: true}
	raw, err := json.Marshal(cancel)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if err = pm2ConfigCreate(d.modulePrivateDirectory, in.PM2OperationID+".cancel.json", raw); err != nil {
		return nil, errors.New("PM2 取消回执未确认；请只读核对原操作，不重发配置保存")
	}
	record := pm2ConfigRecord{Cancellation: &cancel, Raw: raw, SHA: pm2ConfigHash(raw)}
	return map[string]any{"configuration_inventory_complete": true, "configuration_transactions": []any{publicPM2Config(record)}, "request_cancelled": true, "live_configuration_changed": false, "automatic_replay": false}, nil
}

func (s *Service) applyPM2Configuration(ctx context.Context, in core.AppModuleInput, before []byte, app pm2App, st pm2UnitState) (any, error) {

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if st.ActiveState == "active" {
		if err := s.pm2RootVendorReady(ctx); err != nil {
			return nil, err // No intent, new cipher publication, restart or implicit repair.
		}
	}
	current, err := s.pm2ConfigLiveBytes(app.ID)
	if err != nil || !bytes.Equal(current, before) {
		return nil, errors.New("PM2 原配置在保存前已变化")
	}
	after, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return nil, err
	}
	after = append(after, '\n')
	owner, err := currentModuleApplyOwner()
	if err != nil {
		return nil, err
	}
	boot, err := currentPM2ConfigBoot()
	if err != nil {
		return nil, err
	}
	id, requestSHA, err := pm2ConfigurationIdentity(in, before)
	if err != nil {
		return nil, err
	}
	intent := pm2ConfigIntent{Format: 1, ID: id, AppID: app.ID, SiteID: app.SiteID, CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: requestSHA, Before: before, After: after, BeforeSHA: pm2ConfigHash(before), AfterSHA: pm2ConfigHash(after), BeforeState: st}
	if err = validatePM2ConfigIntent(intent); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	d, err := s.openPM2ConfigStore(true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	records, err := d.records()
	if err != nil {
		return nil, err
	}
	if len(records) >= pm2ConfigIntentLimit || pm2ConfigPending(records, app.ID) {
		return nil, errors.New("PM2 配置事务未完成或达到保留上限；未修改配置")
	}
	if _, exists := records[id]; exists {
		return nil, errors.New("PM2 原操作标识已存在；只读刷新原记录，不重复执行")
	}
	if err = pm2ConfigCreate(d.modulePrivateDirectory, id+".intent.json", raw); err != nil {
		return nil, errors.New("PM2 原配置事务无法持久保存，未修改项目；请核对原记录")
	}
	record := pm2ConfigRecord{Intent: intent, SHA: pm2ConfigHash(raw), Raw: raw}
	if err = s.pm2ConfigPublish(app.ID, id, before, after); err != nil {
		return nil, errors.New("PM2 配置发布未完成；原事务保留，请只读核对并恢复")
	}
	unit := "panel-pm2@" + app.ID + ".service"
	if st.ActiveState == "inactive" {
		if err = d.finish(record, "committed"); err != nil {
			return nil, errors.New("PM2 配置已保存但持久回执未确认；保持停止，请核对原事务")
		}
		record.Receipt = &pm2ConfigReceipt{State: "committed"}
		return map[string]any{"app": publicPM2App(app), "ok": true, "service_active": false, "boot_enabled": st.UnitFileState == "enabled", "runtime_validated": false, "preserved_stopped": true, "configuration_transaction": publicPM2Config(record)}, nil
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", unit); err == nil {
		err = s.pm2Ready(ctx, unit, app.Port)
	}
	if err == nil {
		state, e := s.readPM2UnitState(ctx, unit)
		if e != nil || state.ActiveState != "active" || state.UnitFileState != st.UnitFileState {
			err = errors.New("PM2 候选运行或开机设置未确认")
		}
	}
	if err != nil {
		original := err
		rollback, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, stopErr := s.Config.Run(rollback, "/usr/bin/systemctl", "stop", unit)
		stopped, stateErr := s.readPM2UnitState(rollback, unit)
		if stopErr != nil || stateErr != nil || stopped.ActiveState != "inactive" || stopped.UnitFileState != st.UnitFileState {
			return nil, errors.New("PM2 候选停止未确认；未覆盖配置，原事务保留，请显式恢复")
		}
		if e := s.pm2ConfigPublish(app.ID, id, after, before); e != nil {
			return nil, errors.New("PM2 旧配置恢复未确认，原事务保留；未额外重启")
		}
		old, _ := pm2ConfigApp(before)
		_, restartErr := s.Config.Run(rollback, "/usr/bin/systemctl", "restart", unit)
		if restartErr == nil {
			restartErr = s.pm2Ready(rollback, unit, old.Port)
		}
		if restartErr != nil {
			return nil, errors.New("PM2 旧配置已恢复，原服务启动未确认；原事务保留，请只读核对")
		}
		restored, checkErr := s.readPM2UnitState(rollback, unit)
		if checkErr != nil || restored.ActiveState != "active" || restored.UnitFileState != st.UnitFileState {
			return nil, errors.New("PM2 原服务或开机设置未确认；原事务保留")
		}
		if e := d.finish(record, "rolled_back"); e != nil {
			return nil, errors.New("PM2 旧服务已恢复但持久回执未确认；请核对原事务，不重复保存")
		}
		return nil, original
	}
	if err = d.finish(record, "committed"); err != nil {
		return nil, errors.New("PM2 候选已就绪但持久回执未确认；请核对原事务，不重复保存")
	}
	record.Receipt = &pm2ConfigReceipt{State: "committed"}
	return map[string]any{"app": publicPM2App(app), "ok": true, "configuration_transaction": publicPM2Config(record)}, nil
}
