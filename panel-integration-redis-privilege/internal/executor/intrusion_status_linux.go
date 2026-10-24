//go:build linux

package executor

import (
	"context"

	"local/panel/internal/core"
)

// The cheap closed-record gate precedes ANY manifest read. In particular a
// half-removed manifest cannot be reported as a completed uninstallation.
// Existing SH observation never creates a lock or authorizes a writer.
func (s *Service) inspectIntrusionClosed(ctx context.Context) (intrusionInspection, error) {
	var out intrusionInspection
	lock, err := s.intrusionObservationLock()
	if err != nil {
		return out, err
	}
	if lock != nil {
		defer lock.Close()
	}
	if err = s.intrusionJournalRequireClosed(); err != nil {
		return out, err
	}
	out, err = s.inspectIntrusion(ctx)
	if err != nil {
		return out, err
	}
	if err = s.intrusionObservationLockCurrent(lock); err != nil {
		return intrusionInspection{}, err
	}
	if err = s.intrusionJournalRequireClosed(); err != nil {
		return intrusionInspection{}, err
	}
	return out, nil
}

func (s *Service) intrusionSoftwareStatus(ctx context.Context) core.SoftwareAppStatus {
	inspection, err := s.inspectIntrusionClosed(ctx)
	out := core.SoftwareAppStatus{ID: "intrusion-prevention"}
	if err != nil {
		out.StateUnknown = true
		out.Detail = "防入侵原事务或实际状态尚未完整核对；未认定未安装、健康或整体成功"
		return out
	}
	out.Installed, out.Enabled, out.Healthy = inspection.Installed, inspection.ServiceActive, inspection.Healthy
	out.Version, out.Detail = inspection.Version, inspection.Detail
	if inspection.Installed {
		out.Settings = map[string]any{}
		for name, value := range inspection.Settings {
			out.Settings[name] = value
		}
	}
	return out
}
