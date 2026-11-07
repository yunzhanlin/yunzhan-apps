//go:build linux

package executor

import (
	"errors"
	"os"

	"local/panel/internal/core"
)

func integrityKernelApplicationArgument(application []string) (string, error) {
	if len(application) == 0 {
		return core.IntegrityKernelWebsiteApplication, nil
	}
	if len(application) == 1 && core.ValidIntegrityKernelApplication(application[0]) {
		return application[0], nil
	}
	return "", errors.New("内核保护应用身份无效；未选择默认应用替代未知来源")
}

func integrityKernelPlanApplication(plan integrityKernelPlan) string {
	if plan.Format == 1 && plan.AppID == "" {
		return core.IntegrityKernelWebsiteApplication
	}
	if plan.Format == 2 && plan.AppID == core.IntegrityKernelEnterpriseApplication {
		return core.IntegrityKernelEnterpriseApplication
	}
	return ""
}

// Keep the published Root-private journal path and original inodes. An
// enterprise-only installation may create the fixed empty legacy anchor, but
// never an installed.json receipt, baseline or a second independent journal.
// Both applications then use the same per-site revision and release budget.
func (s *Service) integrityKernelEnsureSharedAnchor() error {
	if d, err := s.moduleRecordDirectory(integrityKernelModule); err == nil {
		d.Close()
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	d, err := s.moduleRecordDirectory(core.IntegrityKernelEnterpriseApplication)
	if err != nil {
		return err
	}
	defer d.Close()
	if !d.current() || d.sharedContainer == nil {
		return errors.New("共享保护记录父目录身份不能核对")
	}
	if err = d.sharedContainer.Mkdir(integrityKernelModule, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := d.sharedContainer.Open(".")
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil || !d.current() {
		return errors.New("共享保护记录父目录保存不能核对；原目录保留")
	}
	check, err := s.moduleRecordDirectory(integrityKernelModule)
	if err != nil {
		return err
	}
	check.Close()
	return nil
}
