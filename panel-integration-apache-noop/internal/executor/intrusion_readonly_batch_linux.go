//go:build linux

package executor

import (
	"context"
	_ "embed"
	"errors"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// An independent standard-library-only read helper, not a plugin or a caller
// script. Its sole argument is a canonical live systemd PID. Socket peer PID,
// root ownership and a primitive-only bounded protocol are checked before use.
//
//go:embed intrusion_readonly_batch.py
var intrusionReadOnlyBatchBody string

var intrusionReadOnlyBatchScript = intrusionProcessIdentityScript + "\n" + intrusionFilterMetadataScript + "\n" + intrusionReadOnlyBatchBody

type intrusionReadOnlyBatchObservation struct {
	Args  []string `json:"args"`
	OK    bool     `json:"ok"`
	Value string   `json:"value"`
}
type intrusionReadOnlyBatch struct {
	Format       int                                 `json:"format"`
	PID          string                              `json:"pid"`
	Version      string                              `json:"version"`
	Observations []intrusionReadOnlyBatchObservation `json:"observations"`
}

func intrusionBatchAllowedArgs(args []string) bool {
	if slices.Equal(args, []string{"status", "sshd"}) {
		return true
	}
	if len(args) == 3 && args[0] == "get" && args[1] == "sshd" {
		return slices.Contains([]string{"actions", "journalmatch", "maxretry", "findtime", "bantime", "maxmatches", "banip", "filter-metadata", "process-start"}, args[2])
	}
	if len(args) == 4 && args[0] == "get" && args[1] == "sshd" && args[2] == "actionproperties" {
		return slices.Contains([]string{"nftables", "nftables-multiport"}, args[3])
	}
	return len(args) == 5 && args[0] == "get" && args[1] == "sshd" && args[2] == "action" && slices.Contains([]string{"nftables", "nftables-multiport"}, args[3]) && slices.Contains([]string{"name", "port", "protocol", "chain", "table", "table_family", "addr_set", "addr_set?family=inet6", "actionstart"}, args[4])
}

func intrusionDecodeReadOnlyBatch(raw []byte, pid string) (map[string]intrusionReadOnlyBatchObservation, error) {
	var result intrusionReadOnlyBatch
	if len(raw) < 1 || len(raw) > 32<<10 || decodeProgramQueueJSON(raw, &result) != nil || result.Format != 1 || result.PID != pid || result.Version != "1.0.2" && result.Version != "1.1.0" || len(result.Observations) < 8 || len(result.Observations) > 32 {
		return nil, errors.New("入侵防护批量只读响应的身份、格式或容量无法核对")
	}
	values := map[string]intrusionReadOnlyBatchObservation{}
	for _, item := range result.Observations {
		if !intrusionBatchAllowedArgs(item.Args) || len(item.Value) > 24<<10 || !utf8.ValidString(item.Value) || strings.ContainsRune(item.Value, 0) || !item.OK && item.Value != "" {
			return nil, errors.New("入侵防护批量响应含未知命令、私有错误或超限值")
		}
		key := strings.Join(item.Args, "\x00")
		if _, exists := values[key]; exists {
			return nil, errors.New("入侵防护批量响应命令重复")
		}
		values[key] = item
	}
	for _, args := range [][]string{{"status", "sshd"}, {"get", "sshd", "actions"}, {"get", "sshd", "journalmatch"}, {"get", "sshd", "maxretry"}, {"get", "sshd", "findtime"}, {"get", "sshd", "bantime"}, {"get", "sshd", "banip"}, {"get", "sshd", "maxmatches"}, {"get", "sshd", "filter-metadata"}} {
		if _, exists := values[strings.Join(args, "\x00")]; !exists {
			return nil, errors.New("入侵防护批量响应不是完整固定读范围")
		}
	}
	var metadata intrusionFilterMetadata
	entry := values["get\x00sshd\x00filter-metadata"]
	if !entry.OK || len(entry.Value) > 256 || decodeProgramQueueJSON([]byte(entry.Value), &metadata) != nil || !intrusionFilterMetadataValid(metadata) || metadata.Version != result.Version {
		return nil, errors.New("批量过滤器可读元数据缺失、格式或版本不一致")
	}
	start, exists := values["get\x00sshd\x00process-start"]
	if !exists || !start.OK || !strings.HasSuffix(start.Value, "\n") || !intrusionProcessTicksValid(strings.TrimSuffix(start.Value, "\n")) {
		return nil, errors.New("批量实际进程起始身份缺失或不可核对")
	}
	return values, nil
}

// Fetch one batch BEFORE nft and one AFTER nft, not two prefetched samples.
// The first repeated read marks phase two; a third phase is forbidden. All
// static observations must agree across phases. Dynamic IPs are separately
// compared by the original inspector/runtime snapshot against actual kernel
// sets; failure counters are not invented by the Jail-existence compatibility
// entry. No write/reload/ban command can enter this read adapter.
func (s *Service) intrusionReadOnlySession(ctx context.Context) func(string, ...string) (string, error) {
	if s.Config.SystemRoot != "/" {
		return func(program string, args ...string) (string, error) { return s.Config.Run(ctx, program, args...) }
	}
	var values, original map[string]intrusionReadOnlyBatchObservation
	used := map[string]bool{}
	phases := 0
	pid := ""
	var failure error
	load := func() error {
		if phases >= 2 {
			return errors.New("入侵防护只读采样超过固定两阶段，未执行额外请求")
		}
		if pid == "" {
			raw, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "fail2ban.service", "--property=MainPID,ActiveState")
			if err != nil {
				return errors.New("入侵防护只读服务进程无法核对")
			}
			pid, err = intrusionFail2banProcess(raw)
			if err != nil {
				return err
			}
		}
		raw, err := s.Config.Run(ctx, "/usr/bin/python3", "-I", "-B", "-c", intrusionReadOnlyBatchScript, pid)
		if err != nil {
			return errors.New("入侵防护固定只读批次未完成，未重试或执行变更")
		}
		next, err := intrusionDecodeReadOnlyBatch([]byte(raw), pid)
		if err != nil {
			return err
		}
		if original != nil {
			if len(next) != len(original) {
				return errors.New("入侵防护实际动作范围在两阶段之间改变")
			}
			for key, before := range original {
				after, exists := next[key]
				if !exists {
					return errors.New("入侵防护实际读范围在两阶段之间改变")
				}
				if slices.Equal(before.Args, []string{"status", "sshd"}) || slices.Equal(before.Args, []string{"get", "sshd", "banip"}) {
					continue
				}
				if !reflect.DeepEqual(before, after) {
					return errors.New("入侵防护静态配置在实际内核观察前后改变，未确认生效")
				}
			}
		} else {
			original = next
		}
		values = next
		used = map[string]bool{}
		phases++
		return nil
	}
	return func(program string, args ...string) (string, error) {
		if program != "/usr/bin/fail2ban-client" {
			return s.Config.Run(ctx, program, args...)
		}
		if failure != nil {
			return "", failure
		}
		if !intrusionBatchAllowedArgs(args) {
			return "", errors.New("入侵防护只读会话拒绝非固定读取命令")
		}
		key := strings.Join(args, "\x00")
		if values == nil || used[key] {
			if err := load(); err != nil {
				failure = err
				return "", err
			}
		}
		item, exists := values[key]
		if !exists || !item.OK {
			return "", errors.New("入侵防护固定实际属性无法读取")
		}
		used[key] = true
		return item.Value, nil
	}
}
