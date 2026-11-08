package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const RemoteCopyChunkBytes = 256 << 10
const RemoteCopyFileBytes = 8 << 20

var remoteCopyTargetID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
var remoteCopyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func RemoteIndependentBackupAction(action string) bool {
	switch action {
	case "remote-copy-preview", "remote-copies", "copy-remote-backup", "recover-remote-copy", "verify-remote-copy", "retain-remote-copy", "remote-copy-fragments", "retain-remote-copy-fragments":
		return true
	}
	return false
}
func RemoteUnpublishedCopyAction(action string) bool {
	return action == "remote-copy-fragments" || action == "retain-remote-copy-fragments"
}
func RemoteIndependentInventoryAction(action string) bool {
	return action == "remote-copies" || action == "remote-copy-fragments"
}
func DecodeRemoteIndependentInput(action string, raw []byte) (AppModuleInput, error) {
	var out AppModuleInput
	if !RemoteIndependentBackupAction(action) || len(raw) == 0 || len(raw) > 2048 || bytes.ContainsRune(raw, '\\') {
		return out, errors.New("独立备份请求不是固定有界对象")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return out, errors.New("独立备份请求须为对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return out, errors.New("独立备份字段重复或损坏")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, errors.New("独立备份字段不接受null或缺失值")
		}
		var decodeErr error
		switch key {
		case "remote_target_id":
			decodeErr = json.Unmarshal(value, &out.RemoteTargetID)
		case "expected_revision":
			decodeErr = json.Unmarshal(value, &out.ExpectedRevision)
		case "resource_id":
			if RemoteIndependentInventoryAction(action) {
				return out, errors.New("库存查询不接受原事务字段")
			}
			decodeErr = json.Unmarshal(value, &out.ResourceID)
		case "expected_sha", "confirm":
			if action != "copy-remote-backup" && action != "recover-remote-copy" && action != "retain-remote-copy" && action != "retain-remote-copy-fragments" {
				return out, errors.New("只读请求不接受复制或恢复授权")
			}
			if key == "expected_sha" {
				decodeErr = json.Unmarshal(value, &out.ExpectedSHA)
			} else {
				decodeErr = json.Unmarshal(value, &out.Confirm)
			}
		case "limit", "offset":
			if !RemoteIndependentInventoryAction(action) {
				return out, errors.New("所选副本操作不接受分页")
			}
			if key == "limit" {
				decodeErr = json.Unmarshal(value, &out.Limit)
			} else {
				decodeErr = json.Unmarshal(value, &out.Offset)
			}
		default:
			return out, errors.New("独立备份拒绝额外路径、凭据、字段或策略")
		}
		if decodeErr != nil {
			return out, errors.New("独立备份字段类型无效")
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF || !seen["remote_target_id"] || !seen["expected_revision"] || !remoteCopyTargetID.MatchString(out.RemoteTargetID) || out.ExpectedRevision < 1 || out.ExpectedRevision > 1000000000 {
		return out, errors.New("独立备份连接、修订或完整对象无效")
	}
	if RemoteIndependentInventoryAction(action) {
		if out.Limit < 0 || out.Limit > 32 || out.Offset < 0 || out.Offset > 128 {
			return out, errors.New("独立副本分页超限")
		}
		return out, nil
	}
	if !seen["resource_id"] || !ValidID(out.ResourceID) {
		return out, errors.New("原归档事务标识无效")
	}
	if action == "copy-remote-backup" || action == "recover-remote-copy" || action == "retain-remote-copy" || action == "retain-remote-copy-fragments" {
		prefix := "COPY BACKUP "
		if action == "recover-remote-copy" {
			prefix = "RECOVER COPY "
		} else if action == "retain-remote-copy" {
			prefix = "RETAIN COPY "
		} else if action == "retain-remote-copy-fragments" {
			prefix = "RETAIN FRAGMENTS "
		}
		if !remoteCopyDigest.MatchString(out.ExpectedSHA) || out.Confirm != prefix+out.ResourceID {
			return out, errors.New("独立备份须核对完整原摘要与精确确认")
		}
	}
	return out, nil
}

type RemoteIndependentChunk struct {
	Target       string `json:"remote_target_id"`
	Transaction  string `json:"backup_transaction_id"`
	Name         string `json:"name"`
	IntentSHA    string `json:"intent_sha256"`
	FileSHA      string `json:"file_sha256"`
	FileBytes    int64  `json:"file_bytes"`
	Part         int    `json:"part"`
	Bytes        []byte `json:"data"`
	ChunkSHA     string `json:"chunk_sha256"`
	FilesChanged bool   `json:"files_changed"`
}

func RemoteIndependentReadPath(target, transaction, name, part, digest string) (int, error) {
	v, err := strconv.Atoi(part)
	if !remoteCopyTargetID.MatchString(target) || !ValidID(transaction) || name != "previous" && name != "staged" || !remoteCopyDigest.MatchString(digest) || err != nil || v < 0 || v >= RemoteCopyFileBytes/RemoteCopyChunkBytes || strconv.Itoa(v) != part {
		return 0, errors.New("独立备份下载只接受固定标识、原意图摘要与有界分段")
	}
	return v, nil
}
func ValidateRemoteIndependentChunk(v RemoteIndependentChunk, target, transaction, name string, part int, intentSHA string) error {
	if part < 0 || part >= RemoteCopyFileBytes/RemoteCopyChunkBytes {
		return errors.New("独立副本分段越界")
	}
	expected := min(int64(RemoteCopyChunkBytes), v.FileBytes-int64(part*RemoteCopyChunkBytes))
	if v.Target != target || v.Transaction != transaction || v.Name != name || v.Part != part || v.IntentSHA != intentSHA || !remoteCopyDigest.MatchString(v.FileSHA) || v.FileBytes < 0 || v.FileBytes > RemoteCopyFileBytes || expected < 0 || int64(len(v.Bytes)) != expected || v.ChunkSHA != Hash(string(v.Bytes)) || v.FilesChanged {
		return errors.New("独立备份分段身份、容量或摘要不符，未返回内容")
	}
	return nil
}
func (a *Server) remoteIndependentDownloadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/files-sync/independent-backups/{target}/{transaction}/{name}/chunks/{part}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		access, err := a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "Root私有独立备份仅完整管理员可下载")
			return
		}
		query := r.URL.Query()
		if len(query) != 1 || len(query["sha"]) != 1 {
			fail(w, 400, "下载不接受额外参数或文件路径")
			return
		}
		target, transaction, name, part := r.PathValue("target"), r.PathValue("transaction"), r.PathValue("name"), r.PathValue("part")
		partNumber, inputErr := RemoteIndependentReadPath(target, transaction, name, part, query.Get("sha"))
		if inputErr != nil {
			fail(w, 400, inputErr.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var status struct {
			Status SoftwareAppStatus `json:"status"`
		}
		if a.Executor.Call(ctx, "GET", "/v1/app-modules/files-sync", nil, &status) != nil || !knownInstalledAppModule("files-sync", status.Status) || !appcatalog.FilesSyncIndependentBackupSupported(status.Status.Version) {
			fail(w, 409, "文件同步2.0.0安装身份待核对，未读取备份")
			return
		}
		var out RemoteIndependentChunk
		path := "/v1/app-modules/files-sync/independent-backups/" + target + "/" + transaction + "/" + name + "/chunks/" + part + "?sha=" + url.QueryEscape(query.Get("sha"))
		if err := a.Executor.Call(ctx, "GET", path, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if err := ValidateRemoteIndependentChunk(out, target, transaction, name, partNumber, query.Get("sha")); err != nil {
			fail(w, 409, err.Error())
			return
		}
		access, err = a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "下载权限已变化，未返回私有备份内容")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		send(w, 200, out)
	}))
}
