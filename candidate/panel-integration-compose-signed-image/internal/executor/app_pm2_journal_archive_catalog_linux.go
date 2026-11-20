//go:build linux

package executor

import (
	"errors"
	"os"
	"sort"

	"local/panel/internal/core"
)

func (s *Service) pm2ArchiveChildNames(kind string) ([]string, error) {
	d, err := s.openPM2ArchivePath(kind, "", false)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := pm2ArchiveNames(d, pm2ConfigurationArchiveGenerations)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if !core.ValidID(name) {
			return nil, errors.New("PM2 archive complete inventory contains an unknown identity")
		}
		info, err := d.Lstat(name)
		if err != nil || !moduleRecordInfo(info, true, false) || !d.current() {
			return nil, errors.New("PM2 archive complete inventory contains an unverified directory")
		}
	}
	return names, nil
}
func (s *Service) pm2ArchiveCatalogue() ([]pm2ArchiveRequestObservation, error) {
	anchor, anchorErr := s.moduleRecordDirectory("pm2-manager")
	if errors.Is(anchorErr, os.ErrNotExist) {
		return []pm2ArchiveRequestObservation{}, nil
	}
	if anchorErr != nil {
		return nil, anchorErr
	}
	defer anchor.Close()
	requestIDs, err := s.pm2ArchiveChildNames("requests")
	if err != nil {
		return nil, err
	}
	generations, err := s.pm2ArchiveChildNames("generations")
	if err != nil {
		return nil, err
	}
	generationIDs := map[string]bool{}
	for _, id := range generations {
		generationIDs[id] = true
	}
	rows := make([]pm2ArchiveRequestObservation, 0, len(requestIDs))
	var bytes int
	for _, id := range requestIDs {
		row, err := s.readPM2ArchiveRequest(id)
		if err != nil {
			return nil, err
		}
		bytes += row.StoredBytes
		if bytes > 256<<20 {
			return nil, errors.New("PM2 archive complete metadata inventory exceeds its byte budget")
		}
		exists := generationIDs[id]
		if row.Intent == nil && exists {
			return nil, errors.New("PM2 archive data has no verifiable original intent; retained")
		}
		if row.Outcome != nil {
			if row.Outcome.State == "archived" {
				if !exists || row.Prepared != nil {
					return nil, errors.New("PM2 archive original completion and directory inventory disagree")
				}
				observed, err := s.pm2ArchiveGenerationInfo(id)
				if err != nil || observed == nil || observed.UID != row.Intent.Inventory.Directory.UID || observed.GID != row.Intent.Inventory.Directory.GID || observed.Mode != row.Intent.Inventory.Directory.Mode {
					return nil, errors.New("PM2 archive original directory ownership cannot be verified")
				}
			} else if exists {
				return nil, errors.New("PM2 non-archived outcome still has generation data; retained")
			}
		}
		delete(generationIDs, id)
		rows = append(rows, row)
	}
	if len(generationIDs) != 0 {
		return nil, errors.New("PM2 archive data inventory contains an orphan generation; retained")
	}
	// Re-list complete identities. A concurrent reservation or relocation must
	// not be presented as an empty or fully terminal catalogue.
	again, err := s.pm2ArchiveChildNames("requests")
	if err != nil || len(again) != len(requestIDs) {
		return nil, errors.New("PM2 archive request inventory changed during observation")
	}
	for i := range again {
		if again[i] != requestIDs[i] {
			return nil, errors.New("PM2 archive request namespace changed")
		}
	}
	again, err = s.pm2ArchiveChildNames("generations")
	if err != nil || len(again) != len(generations) {
		return nil, errors.New("PM2 archive data inventory changed during observation")
	}
	for i := range again {
		if again[i] != generations[i] {
			return nil, errors.New("PM2 archive data namespace changed")
		}
	}
	if !anchor.current() {
		return nil, errors.New("PM2 archive module namespace changed during observation")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

// Call under the journal lease before a new configuration mutation. Reads,
// existing service startup and independent stop do not replay or complete a
// pending archive merely because they observe it.
func (s *Service) pm2NoPendingConfigurationArchives() error {
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Intent != nil && row.Outcome == nil {
			return errors.New("PM2 原配置归档尚未完成，请先读取原请求并显式恢复；未保存新的配置")
		}
	}
	return nil
}

// A completed generation is immutable evidence, not a source of fresh writes.
// Match original raw bytes and recorded UID/GID/mode through fresh no-follow
// handles. Device/inode timestamps remain witnesses for unfinished moves, not
// permanent identifiers that would invalidate a legitimate completed backup.
func (s *Service) pm2ArchivedConfigurationRecord(operation string) (pm2ConfigRecord, bool, error) {
	if !core.ValidID(operation) {
		return pm2ConfigRecord{}, false, errors.New("PM2 original configuration operation identity is invalid")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil {
		return pm2ConfigRecord{}, false, err
	}
	var selected *pm2ArchiveRequestObservation
	for i := range rows {
		row := &rows[i]
		if row.Intent == nil || row.Outcome == nil || row.Outcome.State != "archived" {
			continue
		}
		_, intent := row.Intent.Inventory.Files[operation+".intent.json"]
		_, cancel := row.Intent.Inventory.Files[operation+".cancel.json"]
		if !intent && !cancel {
			continue
		}
		if selected != nil {
			return pm2ConfigRecord{}, true, errors.New("PM2 original operation appears in multiple archived generations")
		}
		selected = row
	}
	if selected == nil {
		return pm2ConfigRecord{}, false, nil
	}
	d, err := s.openPM2ArchivePath("generations", selected.ID, false)
	if err != nil {
		return pm2ConfigRecord{}, true, err
	}
	defer d.Close()
	files := map[string][]byte{}
	for _, suffix := range []string{".intent.json", ".result.json", ".cancel.json"} {
		name := operation + suffix
		pin, exists := selected.Intent.Inventory.Files[name]
		if !exists {
			continue
		}
		before, err := d.Lstat(name)
		if err != nil {
			return pm2ConfigRecord{}, true, err
		}
		raw, err := pm2ConfigRead(d, name)
		if err != nil {
			return pm2ConfigRecord{}, true, err
		}
		after, err := d.Lstat(name)
		identity, identityErr := pm2JournalIdentityOf(after)
		if err != nil || identityErr != nil || !programQueueSame(before, after) || identity.UID != pin.Identity.UID || identity.GID != pin.Identity.GID || identity.Mode != pin.Identity.Mode || identity.Links != 1 || identity.Size != pin.Identity.Size || pm2ConfigHash(raw) != pin.SHA256 {
			return pm2ConfigRecord{}, true, errors.New("PM2 archived original operation bytes or recorded ownership changed; retained")
		}
		files[name] = raw
	}
	records, err := decodePM2ConfigurationRecords(files)
	if err != nil {
		return pm2ConfigRecord{}, true, err
	}
	record, found := records[operation]
	if !found || record.Receipt == nil && record.Cancellation == nil {
		return pm2ConfigRecord{}, true, errors.New("PM2 archived original operation is not terminal")
	}
	if err := pm2ConfigSync(d); err != nil {
		return pm2ConfigRecord{}, true, err
	}
	return record, true, nil
}

// An archived nonce remains consumed even after its original files leave the
// active 512-record journal. Never turn missing active history into a fresh
// update/cancellation of an old operation.
func (s *Service) pm2ConfigurationDuplicateIncludingArchives(in core.AppModuleInput, before []byte, active map[string]pm2ConfigRecord) (any, bool, error) {
	if out, known, err := pm2ConfigurationDuplicate(in, before, active); known {
		return out, known, err
	}
	id, _, err := pm2ConfigurationIdentity(in, before)
	if err != nil {
		return nil, true, err
	}
	archived, found, err := s.pm2ArchivedConfigurationRecord(id)
	if err != nil {
		return nil, true, err
	}
	if !found {
		return nil, false, nil
	}
	return pm2ConfigurationDuplicate(in, before, map[string]pm2ConfigRecord{id: archived})
}
