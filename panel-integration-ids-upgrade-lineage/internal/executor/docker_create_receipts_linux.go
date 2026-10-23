//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"local/panel/internal/core"
)

type composeCreateReceipt struct {
	Format     int    `json:"format"`
	JobID      string `json:"job_id"`
	ProjectID  string `json:"project_id"`
	RequestSHA string `json:"request_sha"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
}

var composeRequestSHAPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var errComposeReceipt = errors.New("原始 Compose 创建回执不完整或身份已改变；保留原任务，未重新创建")

func composeReceiptDirectory(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil || real != root || !filepath.IsAbs(root) || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errComposeReceipt
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errComposeReceipt
	}
	return nil
}
func readComposeCreateReceipt(root, id string) (composeCreateReceipt, error) {
	var receipt composeCreateReceipt
	if !core.ValidID(id) {
		return receipt, errComposeReceipt
	}
	if err := composeReceiptDirectory(root); err != nil {
		return receipt, err
	}
	name := filepath.Join(root, id+".compose.intent.json")
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return receipt, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return receipt, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Size() < 2 || info.Size() > 4096 {
		return receipt, errComposeReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return receipt, errComposeReceipt
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return receipt, errComposeReceipt
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(raw, canonical) || receipt.Format != 1 || receipt.JobID != id || !core.ValidID(receipt.ProjectID) || !composeRequestSHAPattern.MatchString(receipt.RequestSHA) || !dockerResourceNamePattern.MatchString(receipt.Name) || len(receipt.Name) > 40 || receipt.TemplateID != "" && !core.IsDockerTemplate(receipt.TemplateID) {
		return receipt, errComposeReceipt
	}
	named, err := os.Lstat(name)
	if err != nil || !os.SameFile(info, named) || named.Mode() != info.Mode() || named.Size() != info.Size() {
		return receipt, errComposeReceipt
	}
	if err := composeReceiptDirectory(root); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// Only the creator of the exclusive receipt may enqueue. A partial original
// receipt remains a refusal, never permission to repair or replace the intent.
func claimComposeCreate(root string, op composeProjectRequest) (bool, error) {
	if err := validateComposeRequest(op); err != nil {
		return false, err
	}
	if op.Action != "create" || !core.ValidID(op.JobID) || !core.ValidID(op.ProjectID) || !composeRequestSHAPattern.MatchString(op.RequestSHA) {
		return false, errComposeReceipt
	}
	if err := composeReceiptDirectory(root); err != nil {
		return false, err
	}
	wanted := composeCreateReceipt{1, op.JobID, op.ProjectID, op.RequestSHA, op.Name, op.TemplateID}
	err := writeExclusiveJSON(filepath.Join(root, op.JobID+".compose.intent.json"), wanted)
	if err == nil {
		dir, e := os.Open(root)
		if e != nil {
			return false, e
		}
		defer dir.Close()
		if e := dir.Sync(); e != nil {
			return false, e
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return false, err
	}
	original, err := readComposeCreateReceipt(root, op.JobID)
	if err != nil {
		return false, err
	}
	if original != wanted {
		return false, errors.New("同一创建请求不能更改原项目或参数；未创建其他任务")
	}
	return false, nil
}
func composeCreateStatus(root, id string, readResult func(string) (core.DockerJobResult, error)) (core.DockerCreateRequestStatus, error) {
	receipt, err := readComposeCreateReceipt(root, id)
	if errors.Is(err, os.ErrNotExist) {
		return core.DockerCreateRequestStatus{Found: false}, nil
	}
	if err != nil {
		return core.DockerCreateRequestStatus{}, err
	}
	out := core.DockerCreateRequestStatus{Found: true, JobID: id, ProjectID: receipt.ProjectID}
	result, err := readResult(id)
	if errors.Is(err, os.ErrNotExist) {
		out.Pending = true
		out.Error = "原请求已保存，尚未确认执行状态；仅核对原任务，不重新创建"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if result.JobID != id || result.ProjectID != receipt.ProjectID || result.Kind != "compose" {
		return out, errComposeReceipt
	}
	switch result.State {
	case "queued", "running", "succeeded", "failed":
	default:
		return out, errComposeReceipt
	}
	if len(result.Error) > 4096 || result.State != "failed" && result.Error != "" {
		return out, errComposeReceipt
	}
	out.Job = &result
	return out, nil
}
