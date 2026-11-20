//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
)

// Historical pages bind every original byte and recorded owner, while using
// fresh private handles after legitimate completed backup restoration.
func (s *Service) pm2ConfigurationArchiveRecords(id string, in core.AppModuleInput) (out any, err error) {
	if !core.ValidID(id) {
		return nil, errors.New("原配置归档标识无效")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil {
		return nil, err
	}
	var selected *pm2ArchiveRequestObservation
	for i := range rows {
		if rows[i].ID == id {
			selected = &rows[i]
			break
		}
	}
	if selected == nil || selected.Intent == nil || selected.Outcome == nil || selected.Outcome.State != "archived" {
		return nil, errors.New("所选原目录未完成封存；未当作成功历史或重放")
	}
	d, err := s.openPM2ArchivePath("generations", id, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, d.Close())
		if err != nil {
			out = nil
		}
	}()
	snapshot, err := (&pm2ConfigStore{modulePrivateDirectory: d}).snapshot()
	if err != nil {
		return nil, err
	}
	pins := selected.Intent.Inventory.Files
	if snapshot.Records != selected.Intent.Inventory.Records || len(snapshot.Files) != len(pins) {
		return nil, errors.New("原封存目录完整记录数量变化，全部保留")
	}
	files := map[string][]byte{}
	for name, recorded := range pins {
		current, found := snapshot.Files[name]
		if !found || current.SHA256 != recorded.SHA256 || current.Identity.UID != recorded.Identity.UID || current.Identity.GID != recorded.Identity.GID || current.Identity.Mode != recorded.Identity.Mode || current.Identity.Links != 1 || current.Identity.Size != recorded.Identity.Size {
			return nil, errors.New("原封存文件摘要或记录的身份变化，未采用其他数据")
		}
		raw, readErr := pm2ConfigRead(d, name)
		if readErr != nil || pm2ConfigHash(raw) != recorded.SHA256 {
			return nil, errors.Join(readErr, errors.New("原封存内容在分页读取期间变化"))
		}
		files[name] = raw
	}
	records, err := decodePM2ConfigurationRecords(files)
	if err != nil {
		return nil, err
	}
	page, err := publicPM2ConfigPage(records, in)
	if err != nil {
		return nil, err
	}
	page["archived_original"] = true
	page["archive_operation_id"] = id
	page["archive_expected_sha"] = selected.IntentSHA
	page["history_or_report_written"] = false
	out = page
	return out, nil
}
