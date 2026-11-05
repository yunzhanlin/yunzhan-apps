//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Stable shared journal anchor: never rename or rewrite published originals.
const integrityKernelModule = "website-tamper-proof"
const integrityKernelRecords = 512
const integrityKernelTargets = 14097 // Existing 10000-file and 4096-directory budgets, plus public root.
const integrityKernelRecordBytes = 16 << 20

// Every original request, plan and outcome is exclusive and retained. Only
// the append-only progress file grows while its original worker owns it.
// An incomplete file is an unknown outcome, never permission to replay.
func (s *Service) integrityKernelStore(create bool) (*modulePrivateDirectory, error) {
	if create {
		if err := s.integrityKernelEnsureSharedAnchor(); err != nil {
			return nil, err
		}
	}
	d, err := s.moduleRecordDirectory(integrityKernelModule)
	if err != nil {
		return nil, err
	}
	if create {
		if err = d.Mkdir("kernel-protection", 0700); err != nil && !errors.Is(err, os.ErrExist) {
			d.Close()
			return nil, err
		}
		parent, e := d.Open(".")
		if e != nil {
			d.Close()
			return nil, e
		}
		err = parent.Sync()
		parent.Close()
		if err != nil {
			d.Close()
			return nil, err
		}
	}
	return integrityKernelChild(d, "kernel-protection")
}

func integrityKernelChild(d *modulePrivateDirectory, name string) (*modulePrivateDirectory, error) {
	before, err := d.Lstat(name)
	if err != nil || !moduleRecordInfo(before, true, false) {
		current := d.current()
		d.Close()
		if err != nil && current {
			return nil, err
		}
		return nil, errors.New("内核保护私有目录身份或权限异常，现场保留")
	}
	child, err := d.OpenRoot(name)
	if err != nil {
		d.Close()
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(before, opened) || !moduleRecordInfo(opened, true, false) {
		child.Close()
		d.Close()
		return nil, errors.New("内核保护目录打开期间变化")
	}
	d.paths = append(d.paths, filepath.Join(d.paths[len(d.paths)-1], name))
	d.roots = append(d.roots, child)
	d.Root = child
	if !d.current() {
		d.Close()
		return nil, errors.New("内核保护父目录变化")
	}
	return d, nil
}

func (s *Service) integrityKernelOperationDirectory(id string) (*modulePrivateDirectory, error) {
	if !core.ValidID(id) {
		return nil, errors.New("内核保护任务标识无效")
	}
	d, err := s.integrityKernelStore(false)
	if err != nil {
		return nil, err
	}
	return integrityKernelChild(d, id)
}

func integrityKernelRead(d *modulePrivateDirectory, name string, limit int64) ([]byte, error) {
	before, err := d.Lstat(name)
	if err != nil {
		if !d.current() {
			return nil, errors.New("内核保护目录变化，不能认定记录缺失")
		}
		return nil, err
	}
	if !moduleRecordInfo(before, false, false) || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("内核保护记录类型、权限、链接或容量异常")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !moduleRecordInfo(opened, false, false) {
		return nil, errors.New("内核保护记录打开身份变化")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	visible, visibleErr := d.Lstat(name)
	if err != nil || statErr != nil || visibleErr != nil || !d.current() || !moduleRecordInfo(after, false, false) || !moduleRecordInfo(visible, false, false) || !os.SameFile(before, after) || !os.SameFile(before, visible) || int64(len(b)) != before.Size() || after.Size() != before.Size() || visible.Size() != before.Size() || after.ModTime() != before.ModTime() || visible.ModTime() != before.ModTime() {
		return nil, errors.New("内核保护记录读取期间变化，请核对原任务")
	}
	return b, nil
}

func integrityKernelCreate(d *modulePrivateDirectory, name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > integrityKernelRecordBytes {
		return errors.New("内核保护记录超过容量，未发布")
	}
	if !d.current() {
		return errors.New("内核保护原目录变化，未发布")
	}
	f, err := d.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	parent, err := d.Open(".")
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	if !d.current() {
		return errors.New("任务可能已保存，但父目录变化；保留原标识核对")
	}
	return nil
}

// Restrict spelling, duplicates, scalar aliases and trailing input before
// decoding Go structs. The same check also covers all nested witness records.
func integrityKernelJSON(raw []byte, value any) error {
	if len(raw) < 1 || len(raw) > integrityKernelRecordBytes || !utf8.Valid(raw) {
		return errors.New("内核保护 JSON 容量无效")
	}
	keys := map[string]bool{}
	var fields func(reflect.Type)
	fields = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name != "" && name != "-" {
				keys[name] = true
			}
			fields(field.Type)
		}
	}
	fields(reflect.TypeOf(value))
	depth, tokens := 0, 0
	var check func(*json.Decoder) error
	check = func(d *json.Decoder) error {
		depth++
		defer func() { depth-- }()
		tokens++
		if depth > 16 || tokens > 1000000 {
			return errors.New("内核保护记录嵌套或对象数量超限")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("内核保护记录不能以 null 替代原值")
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				key, ok := t.(string)
				if e != nil || !ok || !keys[key] || seen[key] {
					return errors.New("内核保护记录字段重复")
				}
				seen[key] = true
				if e = check(d); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("内核保护对象未完整保存")
			}
		case '[':
			for d.More() {
				if e := check(d); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("内核保护数组未完整保存")
			}
		default:
			return errors.New("内核保护 JSON 标记无效")
		}
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := check(d); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("内核保护记录包含尾随内容")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	return integrityKernelApplicationJSON(raw, value)
}

func (s *Service) integrityKernelOperationIDs() ([]string, error) {
	d, err := s.integrityKernelStore(false)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	f, err := d.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(integrityKernelRecords + 1)
	f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > integrityKernelRecords {
		return nil, errors.New("内核保护任务达到 512 份，记录保留且停止新增；请先独立备份维护")
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !core.ValidID(entry.Name()) || !moduleRecordInfo(info, true, false) {
			return nil, errors.New("内核保护库存存在未知、链接或非私有目录，未清理")
		}
		ids = append(ids, entry.Name())
	}
	if !d.current() {
		return nil, errors.New("内核保护库存父目录变化")
	}
	sort.Strings(ids)
	return ids, nil
}

func integrityKernelValidateNames(d *modulePrivateDirectory) error {
	f, err := d.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := f.ReadDir(7)
	f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 6 {
		return errors.New("内核保护任务存在多余或未完成记录，现场保留")
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "request.json", "started.json", "plan.json", "progress.jsonl", "result.json", "closure.json":
		default:
			return errors.New("内核保护任务存在未知文件，未清理")
		}
		info, e := entry.Info()
		if e != nil || !moduleRecordInfo(info, false, false) {
			return errors.New("内核保护任务记录身份或链接异常")
		}
	}
	if !d.current() {
		return errors.New("内核保护任务父目录变化")
	}
	return nil
}
