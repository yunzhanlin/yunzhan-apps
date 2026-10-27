//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

// The same private mount and invalid release envelope remain mandatory. This
// child closes before its BindsTo parent; the earlier unchanged parent-exit
// component is separate evidence. No account is created.
func TestLoadBalanceStreamAccountChildKernelNativeParentRole(t *testing.T) {
	TestLoadBalanceStreamAccountParentKernelNativeParentRole(t)
}

func TestLoadBalanceStreamAccountChildKernelNativeChildRole(t *testing.T) {
	root, job := streamParentKernelFixture(t)
	if os.Getenv("PANEL_LBSTREAM_PARENT_QA_ROLE") != "child" {
		t.Fatal("wrong explicit child role")
	}
	raw := streamParentKernelWait(t, filepath.Join(root, "permit.json"), 5*time.Second)
	p, err := loadbalancestream.DecodeAccountChildPermit(raw)
	if err != nil || p.JobID != job {
		t.Fatal("original private parent permit unavailable", err)
	}
	j, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, job)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := holdLoadBalanceStreamAccountParent(context.Background(), p, j)
	if err != nil {
		j.close()
		t.Fatal("actual original parent unavailable", err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Second)
	defer stop()
	for name, change := range map[string]func(*loadbalancestream.AccountChildPermit){
		"self-pid": func(p *loadbalancestream.AccountChildPermit) { p.ParentPID = uint32(os.Getpid()) },
		"wrong-boot": func(p *loadbalancestream.AccountChildPermit) {
			if p.BootID[0] == 'a' {
				p.BootID = "b" + p.BootID[1:]
			} else {
				p.BootID = "a" + p.BootID[1:]
			}
		},
		"expired": func(p *loadbalancestream.AccountChildPermit) {
			p.CreatedAt = time.Now().Add(-loadbalancestream.AccountChildPermitLifetime - time.Second).UTC().Format(time.RFC3339)
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := p
			change(&altered)
			got, err := holdLoadBalanceStreamAccountParent(ctx, altered, j)
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("foreign or expired parent borrowed the original kernel witness")
			}
		})
	}
	if err := checkLoadBalanceStreamAccountChildKernel(context.Background(), parent); err != nil {
		parent.Close()
		j.close()
		t.Fatal("actual independent child unit/procfs/dependency checks refused", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if checkLoadBalanceStreamAccountChildKernel(ctx, parent) == nil {
			t.Fatal("absent/canceled context borrowed original child authority")
		}
	}
	if checkLoadBalanceStreamAccountChildKernel(context.Background(), nil) == nil {
		t.Fatal("missing parent granted child authority")
	}
	if _, err := j.officialAuthority(context.Background()); err == nil {
		t.Fatal("valid kernel/unit observations upgraded the invalid release envelope")
	}
	body, err := json.Marshal(map[string]any{
		"ok": true, "component_only": true, "actual_child_PID_cgroup_Root_NoNewPrivs_and_fixed_exec_unit": true,
		"actual_BindsTo_and_After_original_live_parent": true, "original_parent_rechecked_before_and_after": true,
		"fake_release_envelope_remained_invalid": true, "NSS_or_account_or_application_effects": 0,
		"commercial_acceptance": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	streamParentKernelWrite(t, filepath.Join(root, "child-self-witness.json"), append(body, '\n'))
	parent.Close()
	j.close()
	result, err := json.Marshal(map[string]any{
		"ok": true, "component_only": true,
		"actual_live_parent_same_exe_original_unit_pidfd_and_write_FLOCK": true,
		"self_pid_wrong_boot_and_expired_refused":                         true,
		"host_executor_namespace_hidden_by_private_tmpfs":                 true,
		"fake_envelope_never_official_authority":                          true, "NSS_or_account_or_application_effects": 0,
		"installer_or_customer_job_replayed": false, "commercial_acceptance": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	streamParentKernelWrite(t, filepath.Join(root, "kernel-witness.json"), append(result, '\n'))
}
