//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/rulefeed"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// A data-only store, distinct from the original indicator rules and all active
// configuration. This type is internal; neither path nor trust is API input.
type threatIDSRuleFeedStore struct {
	base       string
	trust      *appcatalog.Client
	now        func() time.Time
	checkpoint func(string) error // In-process fault injection only.
}

type threatIDSRuleFeedRecord struct {
	Format           int    `json:"format"`
	State            string `json:"state"`
	FeedID           string `json:"feed_id"`
	AppVersion       string `json:"app_version"`
	AppManifestSHA   string `json:"app_manifest_sha256"`
	RuleManifestSHA  string `json:"rule_manifest_sha256"`
	CatalogSHA       string `json:"catalog_sha256"`
	SignatureSHA     string `json:"signature_sha256"`
	TrustKeySHA      string `json:"trust_key_sha256"`
	DataCatalogSHA   string `json:"rule_data_catalog_sha256,omitempty"`
	DataSignatureSHA string `json:"rule_data_signature_sha256,omitempty"`
}

func (s *Service) threatIDSRuleFeedStore() (threatIDSRuleFeedStore, error) {
	if s.Config.SystemRoot != "/" || os.Geteuid() != 0 {
		return threatIDSRuleFeedStore{}, errors.New("规则数据只能由固定 root 安装流程存放")
	}
	return threatIDSRuleFeedStore{base: threatIDSRuleFeedRoot, trust: appcatalog.Default(), now: time.Now}, nil
}

func threatIDSRuleFeedName(feedID, manifestSHA string) string {
	return feedID + "-" + manifestSHA
}

func threatIDSRuleFeedPolicy(now time.Time, id string, bundle *rulefeed.Bundle) error {
	date, err := time.Parse("20060102", strings.TrimPrefix(id, "et-open-web-"))
	if err != nil || now.Before(date) || !now.Before(date.Add(14*24*time.Hour)) || now.Year() < 2026 || bundle == nil || bundle.Manifest.EnabledRuleCount > 2048 {
		return errors.New("规则数据日期、14 天维护窗口或 2048 条预算不符合当前策略")
	}
	allowed := map[string]bool{"HOME_NET": true, "EXTERNAL_NET": true, "HTTP_PORTS": true, "SHELLCODE_PORTS": true, "SSH_PORTS": true}
	for _, variable := range bundle.Manifest.RequiredVariables {
		if !allowed[variable] {
			return errors.New("规则数据需要当前闭合原生配置未提供的变量")
		}
	}
	return nil
}

func (store threatIDSRuleFeedStore) verify(ctx context.Context, in appcatalog.RuleFeedEnvelope, version, appSHA string) (threatIDSRuleFeedRecord, *rulefeed.Bundle, error) {
	var empty threatIDSRuleFeedRecord
	if store.trust == nil || store.now == nil {
		return empty, nil, errors.New("规则数据受信安装环境未初始化")
	}
	_, bundle, err := store.trust.VerifyRuleFeedEnvelopeAt(ctx, in, version, appSHA, store.now())
	if err != nil {
		return empty, nil, err
	}
	if err := threatIDSRuleFeedPolicy(store.now().UTC(), in.FeedID, bundle); err != nil {
		return empty, nil, err
	}
	record := threatIDSRuleFeedRecord{Format: 1, State: "verified-data-only", FeedID: in.FeedID, AppVersion: version, AppManifestSHA: appSHA, RuleManifestSHA: core.Hash(string(bundle.Files["manifest.json"])), CatalogSHA: core.Hash(string(in.Catalog)), SignatureSHA: core.Hash(string(in.Signature)), TrustKeySHA: core.Hash(string(store.trust.PublicKey))}
	if len(in.DataCatalog) > 0 {
		record.Format = 2
		record.DataCatalogSHA = core.Hash(string(in.DataCatalog))
		record.DataSignatureSHA = core.Hash(string(in.DataSignature))
	}
	return record, bundle, nil
}

// Only an already committed configuration or its root-owned recovery journal
// may use this lane. Expiry prevents NEW selection/download, not continuity of
// a previously chosen immutable profile after a reboot. Both signatures and
// every original asset are still rechecked. The result is never exposed as
// fresh authority, passed to install, or used by the activation candidate lane.
func (store threatIDSRuleFeedStore) verifyForCommittedUse(ctx context.Context, in appcatalog.RuleFeedEnvelope, version, appSHA string) (threatIDSRuleFeedRecord, *rulefeed.Bundle, error) {
	if store.trust == nil || store.now == nil || store.now().Year() < 2026 {
		return threatIDSRuleFeedRecord{}, nil, errors.New("已提交规则的受信环境或本机时钟无效")
	}
	var published time.Time
	if len(in.DataCatalog) > 0 || len(in.DataSignature) > 0 {
		authority, err := store.trust.VerifyRetainedRuleDataAuthority(in.Catalog, in.Signature, in.AppManifest, in.DataCatalog, in.DataSignature, version, appSHA, store.now())
		if err != nil {
			return threatIDSRuleFeedRecord{}, nil, err
		}
		published, err = time.Parse(time.RFC3339, authority.Catalog().PublishedAt)
		if err != nil || authority.Catalog().Feed.ID != in.FeedID {
			return threatIDSRuleFeedRecord{}, nil, errors.New("已提交规则的原始发布身份不同")
		}
	} else {
		var err error
		published, err = time.Parse("20060102", strings.TrimPrefix(in.FeedID, "et-open-web-"))
		if err != nil || store.now().UTC().Before(published) {
			return threatIDSRuleFeedRecord{}, nil, errors.New("已提交的旧格式规则日期无效或来自未来")
		}
	}
	retained := store
	retained.now = func() time.Time { return published }
	// Verification at the independently signed publication rechecks the full
	// bundle and variable/resource/license policy; it does not renew its expiry.
	return retained.verify(ctx, in, version, appSHA)
}

func ruleFeedStoreOwned(path string, directory bool, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() || !directory && stat.Nlink != 1 {
		return errors.New("规则数据路径所有者、类型、链接数或权限不同")
	}
	return nil
}

func ruleFeedStoreParents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("规则数据路径必须为明确的绝对目录")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("规则数据父目录为链接、可写或不可核对")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return errors.New("规则数据父目录不属于 root 或当前安装进程")
		}
		if info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("规则数据父目录允许非安装进程改写")
		}
		if current == "/" {
			return nil
		}
	}
}

func (store threatIDSRuleFeedStore) fault(point string) error {
	if store.checkpoint != nil {
		return store.checkpoint(point)
	}
	return nil
}

func ruleFeedStoreWrite(root *os.Root, name string, data []byte, mode os.FileMode) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if n, e := file.Write(data); e != nil || n != len(data) {
		err = fmt.Errorf("规则数据完整写入失败: %v", e)
	}
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	if e := file.Close(); err == nil {
		err = e
	}
	return err
}

func ruleFeedStoreSync(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// install publishes only immutable, independently verified data. It cannot
// execute rules, native commands, modify YAML, start capture or alter boot.
// Failed stages remain private for recovery; no old data is pruned here.
func (store threatIDSRuleFeedStore) install(ctx context.Context, in appcatalog.RuleFeedEnvelope, version, appSHA string) (threatIDSRuleFeedRecord, error) {
	record, bundle, err := store.verify(ctx, in, version, appSHA)
	if err != nil {
		return threatIDSRuleFeedRecord{}, err
	}
	// Detach signed inputs, then independently verify those exact copies too.
	in.Catalog = append([]byte(nil), in.Catalog...)
	in.Signature = append([]byte(nil), in.Signature...)
	in.AppManifest = append([]byte(nil), in.AppManifest...)
	in.DataCatalog = append([]byte(nil), in.DataCatalog...)
	in.DataSignature = append([]byte(nil), in.DataSignature...)
	in.Files = bundle.Files
	if record, bundle, err = store.verify(ctx, in, version, appSHA); err != nil {
		return threatIDSRuleFeedRecord{}, err
	}
	if err := ruleFeedStoreParents(store.base); err != nil {
		return record, err
	}
	if err := ruleFeedStoreOwned(store.base, true, 0755); err != nil {
		return record, err
	}
	if len(in.DataCatalog) > 0 {
		if err := store.channelProgress(ctx, in, version, appSHA); err != nil {
			return record, err
		}
	}
	root, err := os.OpenRoot(store.base)
	if err != nil {
		return record, err
	}
	defer root.Close()
	name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
	if _, err := root.Lstat(name); err == nil {
		return store.read(ctx, name, version, appSHA)
	} else if !errors.Is(err, os.ErrNotExist) {
		return record, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return record, err
	}
	entries, err := dir.ReadDir(9)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) >= 8 {
		return record, errors.New("规则数据最多保留 8 个已发布或失败阶段；未清理旧副本")
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !threatIDSRuleFeedPublished.MatchString(entry.Name()) && !(strings.HasPrefix(entry.Name(), ".stage-") && core.ValidID(strings.TrimPrefix(entry.Name(), ".stage-"))) {
			return record, errors.New("规则数据存放目录存在未知条目；保留而不接管")
		}
	}
	stage := ".stage-" + core.ID()
	if err := root.Mkdir(stage, 0700); err != nil {
		return record, err
	}
	if err := root.Chmod(stage, 0700); err != nil {
		return record, err
	}
	published := false
	defer func() {
		if !published {
			// Never remove the failed bytes. This is our exclusively created
			// stage, not a supplied path or an existing published dataset.
			_ = root.Chmod(stage, 0700)
			_ = ruleFeedStoreSync(root)
		}
	}()
	if err := ruleFeedStoreSync(root); err != nil {
		return record, err
	}
	if err := store.fault("stage-created"); err != nil {
		return record, err
	}
	staged, err := root.OpenRoot(stage)
	if err != nil {
		return record, err
	}
	defer staged.Close()
	for _, asset := range []string{"manifest.json", "et-open.rules", "LICENSE", "BSD-License.txt", "classification.config", "reference.config"} {
		if err := ctx.Err(); err != nil {
			return record, err
		}
		if err := ruleFeedStoreWrite(staged, asset, bundle.Files[asset], 0644); err != nil {
			return record, err
		}
		if err := store.fault("member-written:" + asset); err != nil {
			return record, err
		}
	}
	for _, asset := range []struct {
		name string
		data []byte
	}{{"catalog.json", in.Catalog}, {"catalog.sig", in.Signature}, {"app-manifest.json", in.AppManifest}} {
		if err := ruleFeedStoreWrite(staged, asset.name, asset.data, 0600); err != nil {
			return record, err
		}
	}
	if len(in.DataCatalog) > 0 {
		if err := ruleFeedStoreWrite(staged, "rule-data-catalog.json", in.DataCatalog, 0600); err != nil {
			return record, err
		}
		if err := ruleFeedStoreWrite(staged, "rule-data-catalog.sig", in.DataSignature, 0600); err != nil {
			return record, err
		}
	}
	receipt, err := json.Marshal(record)
	if err != nil {
		return record, err
	}
	if err := ruleFeedStoreWrite(staged, "provenance.json", append(receipt, '\n'), 0600); err != nil {
		return record, err
	}
	if err := ruleFeedStoreSync(staged); err != nil {
		return record, err
	}
	if err := store.fault("data-synced"); err != nil {
		return record, err
	}
	if err := ctx.Err(); err != nil {
		return record, err
	}
	if err := root.Chmod(stage, 0755); err != nil {
		return record, err
	}
	if err := ruleFeedStoreSync(staged); err != nil {
		return record, err
	}
	if err := renameNoReplace(root, stage, name); err != nil {
		if sealErr := root.Chmod(stage, 0700); sealErr != nil {
			return record, errors.New("规则数据发布失败，阶段重新封存失败；保留现场")
		}
		if sealErr := ruleFeedStoreSync(staged); sealErr != nil {
			return record, errors.New("规则数据发布失败，阶段封存落盘失败；保留现场")
		}
		return record, errors.New("规则数据目标已存在或发布失败；未覆盖，保留阶段")
	}
	published = true
	if err := ruleFeedStoreSync(root); err != nil {
		return record, err
	}
	if err := store.fault("published"); err != nil {
		return record, err
	}
	return store.read(ctx, name, version, appSHA)
}

var threatIDSRuleFeedPublished = regexp.MustCompile(`^et-open-web-[0-9]{8}-[0-9a-f]{64}$`)

func ruleFeedStoreRead(root *os.Root, name string, limit int64, mode os.FileMode) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !before.Mode().IsRegular() || before.Mode().Perm() != mode || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("规则数据文件身份、大小或权限不完整")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		return nil, errors.New("规则数据完整读取失败")
	}
	after, err := file.Stat()
	current, currentErr := root.Lstat(name)
	if err != nil || currentErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || before.Sys().(*syscall.Stat_t).Ctim != after.Sys().(*syscall.Stat_t).Ctim {
		return nil, errors.New("规则数据核验期间被替换或改写")
	}
	return data, nil
}

// Read rechecks the original authority, all six bytes, ownership and receipt;
// existence or a persisted 'verified' flag alone never means trusted data.
func (store threatIDSRuleFeedStore) read(ctx context.Context, name, version, appSHA string) (threatIDSRuleFeedRecord, error) {
	return store.readWithPolicy(ctx, name, version, appSHA, false)
}

func (store threatIDSRuleFeedStore) readForCommittedUse(ctx context.Context, name, version, appSHA string) (threatIDSRuleFeedRecord, error) {
	return store.readWithPolicy(ctx, name, version, appSHA, true)
}

func (store threatIDSRuleFeedStore) readWithPolicy(ctx context.Context, name, version, appSHA string, committed bool) (threatIDSRuleFeedRecord, error) {
	var record threatIDSRuleFeedRecord
	if !threatIDSRuleFeedPublished.MatchString(name) || ruleFeedStoreParents(store.base) != nil || ruleFeedStoreOwned(store.base, true, 0755) != nil || ruleFeedStoreOwned(filepath.Join(store.base, name), true, 0755) != nil {
		return record, errors.New("规则数据发布目录身份或模式不完整")
	}
	root, err := os.OpenRoot(store.base)
	if err != nil {
		return record, err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil {
		return record, err
	}
	dataRoot, err := root.OpenRoot(name)
	if err != nil {
		return record, err
	}
	defer dataRoot.Close()
	dir, err := dataRoot.Open(".")
	if err != nil {
		return record, err
	}
	entries, readErr := dir.ReadDir(13)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) != 10 && len(entries) != 12 {
		return record, errors.New("规则数据发布目录不是闭合十或十二文件集合")
	}
	in := appcatalog.RuleFeedEnvelope{FeedID: name[:len(name)-65], Files: map[string][]byte{}}
	for _, asset := range []struct {
		name  string
		limit int64
	}{{"manifest.json", 32 << 10}, {"et-open.rules", 8 << 20}, {"LICENSE", 128 << 10}, {"BSD-License.txt", 128 << 10}, {"classification.config", 128 << 10}, {"reference.config", 128 << 10}} {
		if err := ctx.Err(); err != nil {
			return record, err
		}
		data, err := ruleFeedStoreRead(dataRoot, asset.name, asset.limit, 0644)
		if err != nil {
			return record, err
		}
		in.Files[asset.name] = data
	}
	for _, asset := range []struct {
		name  string
		limit int64
		dest  *[]byte
	}{{"catalog.json", 2 << 20, &in.Catalog}, {"catalog.sig", 4096, &in.Signature}, {"app-manifest.json", 128 << 10, &in.AppManifest}} {
		data, err := ruleFeedStoreRead(dataRoot, asset.name, asset.limit, 0600)
		if err != nil {
			return record, err
		}
		*asset.dest = data
	}
	data, err := ruleFeedStoreRead(dataRoot, "provenance.json", 8192, 0600)
	if err != nil || decodeThreatIDSPrivateJSON(data, &record) != nil {
		return record, errors.New("规则数据私有来源记录损坏或不完整")
	}
	if record.Format == 2 {
		if len(entries) != 12 {
			return record, errors.New("规则数据通道的十二文件交付不完整")
		}
		in.DataCatalog, err = ruleFeedStoreRead(dataRoot, "rule-data-catalog.json", 32<<10, 0600)
		if err != nil {
			return record, err
		}
		in.DataSignature, err = ruleFeedStoreRead(dataRoot, "rule-data-catalog.sig", 4096, 0600)
		if err != nil {
			return record, err
		}
	} else if record.Format != 1 || len(entries) != 10 {
		return record, errors.New("规则数据来源格式与文件集合不符")
	}
	var wanted threatIDSRuleFeedRecord
	if committed {
		wanted, _, err = store.verifyForCommittedUse(ctx, in, version, appSHA)
	} else {
		wanted, _, err = store.verify(ctx, in, version, appSHA)
	}
	if err != nil || record != wanted || threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA) != name {
		return record, errors.New("规则数据原始签名、来源记录或发布身份不能核对")
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return record, errors.New("规则数据目录在核验期间被替换")
	}
	return record, nil
}
