//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// Reviewing an uncertain plan is not fresh authority to delete the same
// snapshot in a different plan. Even after a fresh PID, block subsequent
// automatic deletion while any selected original index/copy remains.
// No path supplied by a caller is used, and no surviving evidence is modified.
func (s *Service) wafRetainedUnknownArchiveIDs(ctx context.Context, record wafBodyRetentionRecord) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	collect := func(op wafBodyRetentionOperation) {
		if op.State == "retained_unknown" {
			for _, id := range op.Plan.Selected {
				selected[id] = true
			}
		}
	}
	if record.Operation != nil {
		collect(*record.Operation)
	}
	for _, op := range record.History {
		collect(op)
	}
	out := []string{}
	if len(selected) == 0 {
		return out, nil
	}
	directory := s.wafBodyLogArchiveDirectory()
	if err := s.wafOwnedDirectory(directory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return out, err
	}
	for id := range selected {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		for _, suffix := range []string{".json", ".log"} {
			_, err := os.Lstat(filepath.Join(directory, id+suffix))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return out, err
			}
			out = append(out, id)
			break
		}
	}
	sort.Strings(out)
	return out, nil
}
