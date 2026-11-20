//go:build linux

package executor

import (
	"errors"
	"os"

	"local/panel/internal/core"
)

// This observation is private. Only a small summary, hashes and record counts
// will be returned by the versioned UI/API; original encrypted manifests and
// recorded filesystem identities are not regenerated or exposed as form data.
type pm2ArchiveRequestObservation struct {
	Restore       *pm2ConfigurationArchiveRestore
	RestoreSHA    string
	StoredBytes   int
	ID            string
	Intent        *pm2ConfigurationArchiveIntent
	IntentSHA     string
	Outcome       *pm2ConfigurationArchiveOutcome
	OutcomeSHA    string
	Fragments     map[string]pm2JournalFilePin
	Prepared      *pm2JournalIdentity
	PreparedEmpty bool
}

func (s *Service) openPM2ArchivePrepared(id string) (*modulePrivateDirectory, error) {
	d, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		return nil, err
	}
	if err = pm2ConfigChild(d, "prepared-new", false); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}
func (s *Service) readPM2ArchiveRequest(id string) (pm2ArchiveRequestObservation, error) {
	result := pm2ArchiveRequestObservation{ID: id, Fragments: map[string]pm2JournalFilePin{}}
	if !core.ValidID(id) {
		return result, errors.New("PM2 archive request identity is invalid")
	}
	d, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		return result, err
	}
	defer d.Close()
	names, err := pm2ArchiveNames(d, 64)
	if err != nil {
		return result, err
	}
	var total int
	for _, name := range names {
		switch {
		case name == "prepared-new":
			prepared, err := s.openPM2ArchivePrepared(id)
			if err != nil {
				return result, err
			}
			info, statErr := prepared.Stat(".")
			if statErr != nil {
				prepared.Close()
				return result, statErr
			}
			identity, identityErr := pm2JournalIdentityOf(info)
			children, readErr := pm2ArchiveNames(prepared, 1)
			closeErr := prepared.Close()
			if identityErr != nil || readErr != nil || closeErr != nil {
				return result, errors.Join(identityErr, readErr, closeErr)
			}
			result.Prepared = &identity
			result.PreparedEmpty = len(children) == 0
		case name == "intent.json":
			raw, err := pm2ArchiveRead(d, name)
			if err != nil {
				return result, err
			}
			total += len(raw)
			var intent pm2ConfigurationArchiveIntent
			if decodeProgramQueueJSON(raw, &intent) != nil || intent.ID != id || validatePM2ConfigurationArchiveIntent(intent) != nil {
				return result, errors.New("PM2 archive original intent cannot be verified; original retained")
			}
			result.Intent = &intent
			result.IntentSHA = pm2ConfigHash(raw)
		case name == "restore.json":
			raw, err := pm2ArchiveRead(d, name)
			if err != nil {
				return result, err
			}
			total += len(raw)
			var restore pm2ConfigurationArchiveRestore
			if decodeProgramQueueJSON(raw, &restore) != nil || restore.ID != id {
				return result, errors.New("PM2 archive restore choice is unverifiable; retained")
			}
			result.Restore = &restore
			result.RestoreSHA = pm2ConfigHash(raw)
		case name == "outcome.json":
			raw, err := pm2ArchiveRead(d, name)
			if err != nil {
				return result, err
			}
			total += len(raw)
			var outcome pm2ConfigurationArchiveOutcome
			if decodeProgramQueueJSON(raw, &outcome) != nil || outcome.ID != id {
				return result, errors.New("PM2 archive original outcome cannot be verified; original retained")
			}
			result.Outcome = &outcome
			result.OutcomeSHA = pm2ConfigHash(raw)
		case pm2ArchivePartName.MatchString(name):
			before, err := d.Lstat(name)
			if err != nil {
				return result, err
			}
			raw, err := pm2ArchiveRead(d, name)
			if err != nil {
				return result, err
			}
			total += len(raw)
			info, err := d.Lstat(name)
			if err != nil {
				return result, err
			}
			if !programQueueSame(before, info) || info.Size() != int64(len(raw)) {
				return result, errors.New("PM2 archive original fragment changed during observation")
			}
			identity, err := pm2JournalIdentityOf(info)
			if err != nil {
				return result, err
			}
			result.Fragments[name] = pm2JournalFilePin{Identity: identity, SHA256: pm2ConfigHash(raw)}
		default:
			return result, errors.New("PM2 archive request contains unknown original evidence; retained")
		}
		if total > 16<<20 {
			return result, errors.New("PM2 archive complete request exceeds its byte budget")
		}
	}
	if result.Restore != nil {
		if result.Intent == nil || validatePM2ConfigurationArchiveRestore(*result.Restore, id, result.IntentSHA) != nil {
			return result, errors.New("PM2 archive restore choice does not bind its original intent")
		}
	}
	if result.Outcome != nil {
		if result.Restore != nil && result.Outcome.State == "archived" {
			return result, errors.New("PM2 archive completion conflicts with its explicit restore choice")
		}
		if result.Intent == nil || validatePM2ConfigurationArchiveOutcome(*result.Outcome, *result.Intent, result.IntentSHA) != nil {
			return result, errors.New("PM2 archive original outcome does not bind its original intent")
		}
	}
	if result.Prepared != nil && result.Intent != nil && !pm2JournalSameMovedDirectory(result.Intent.PreparedDirectory, *result.Prepared) {
		return result, errors.New("PM2 archive prepared directory identity changed; not adopted")
	}
	if err := pm2ConfigSync(d); err != nil {
		return result, err
	}
	// Re-list as a complete observation. A concurrently published final record
	// must not be silently omitted and presented as an unaccepted request.
	again, err := pm2ArchiveNames(d, 64)
	if err != nil {
		return result, err
	}
	if len(again) != len(names) {
		return result, errors.New("PM2 archive request changed during observation")
	}
	for i := range names {
		if names[i] != again[i] {
			return result, errors.New("PM2 archive original request namespace changed")
		}
	}
	result.StoredBytes = total
	return result, nil
}

func (s *Service) pm2ArchiveGenerationInfo(id string) (*pm2JournalIdentity, error) {
	if !core.ValidID(id) {
		return nil, errors.New("PM2 archive generation identity is invalid")
	}
	d, err := s.openPM2ArchivePath("generations", id, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	info, err := d.Stat(".")
	if err != nil || !d.current() {
		return nil, errors.New("PM2 archive generation directory cannot be verified")
	}
	identity, err := pm2JournalIdentityOf(info)
	if err != nil {
		return nil, err
	}
	return &identity, nil
}
