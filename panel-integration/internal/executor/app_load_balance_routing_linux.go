//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"local/panel/internal/core"
)

func validateLoadBalanceRouting(v loadBalanceEntry) error {
	active := core.LoadBalanceAutomaticTraffic(v.HealthCheck)
	if (v.Format == 3) != active || (v.Routing != nil) != active {
		return errors.New("自动健康流量须显式策略、格式 3 和完整运行记录；历史入口不得自动启用")
	}
	if !active {
		return nil
	}
	if v.Routing.Sequence < 0 || v.Routing.Sequence >= 1<<60 || v.Routing.Down == nil || len(v.Routing.Down) > len(v.Nodes) {
		return errors.New("自动流量运行序号或节点记录无效")
	}
	allowed := map[string]bool{}
	for _, n := range v.Nodes {
		allowed[n.Address] = true
	}
	previous := ""
	for _, address := range v.Routing.Down {
		if !allowed[address] || address <= previous {
			return errors.New("摘除节点必须是规范、排序、不重复的已登记固定地址")
		}
		previous = address
	}
	return nil
}

// Format 3 binds configuration, desired/runtime entry and full health state.
// Format 4 additionally binds the unchanged backend CA. No administrative
// policy, node weight, address, TLS trust or policy revision may change here.
func (s *Service) loadBalanceRoutingTransactionContract(tx loadBalanceTransaction, old, next loadBalanceEntry) error {
	if !tx.Changes[0].OldExists || !tx.Changes[0].NextExists || !tx.Changes[1].OldExists || old.Removed || next.Removed ||
		old.Format != 3 || next.Format != 3 || old.Revision != next.Revision ||
		!core.LoadBalanceAutomaticTraffic(old.HealthCheck) || !core.LoadBalanceAutomaticTraffic(next.HealthCheck) {
		return errors.New("自动流量事务只能更新当前活动入口运行状态，不得创建、移除或改换策略")
	}
	if (tx.Format == 4) != (old.BackendTLS != nil || next.BackendTLS != nil) ||
		tx.Changes[2].Path != s.loadBalanceHealthPath(tx.Domain) {
		return errors.New("自动流量事务须绑定当前健康路径以及完整 TLS 信任文件")
	}
	health := tx.Changes[2]
	if !health.NextExists || health.NextMode != 0600 || (health.OldExists && health.OldMode != 0600) {
		return errors.New("自动流量恢复的健康记录权限无效")
	}
	now := time.Now().UTC()
	var previous *loadBalanceHTTPState
	var err error
	if health.OldExists {
		previous, err = decodeLoadBalanceHTTPState(old, health.OldData, now)
		if err != nil {
			return err
		}
	}
	state, err := decodeLoadBalanceHTTPState(next, health.NextData, now)
	if err != nil || state == nil {
		return errors.New("自动流量下一健康记录未通过完整当前身份核对")
	}
	decision := *state
	decision.Fingerprint = loadBalanceFingerprint(old)
	wanted, changed, err := loadBalanceRoutingNext(old, decision)
	if err != nil || !changed {
		return errors.New("自动流量恢复记录没有对应实际阈值变化")
	}
	a, _ := json.Marshal(wanted)
	b, _ := json.Marshal(next)
	if !bytes.Equal(a, b) {
		return errors.New("自动流量事务不得修改管理员策略或伪造运行序号")
	}
	samples := append([]loadBalanceHTTPNode{}, state.Nodes...)
	for i := range samples {
		samples[i].State = "unknown"
		samples[i].Successes = 0
		samples[i].Failures = 0
	}
	completed, err := time.Parse(time.RFC3339Nano, state.CheckedAt)
	if err != nil {
		return err
	}
	expected := advanceLoadBalanceHTTPState(old, previous, samples, completed)
	expected.Fingerprint = loadBalanceFingerprint(next)
	a, _ = json.Marshal(expected)
	b, _ = json.Marshal(state)
	if !bytes.Equal(a, b) {
		return errors.New("自动流量恢复必须保留原检查计数、阈值与全部状态转换")
	}
	rendered, err := s.renderLoadBalanceEntry(next)
	if err != nil || string(tx.Changes[0].NextData) != rendered {
		return errors.New("自动流量下一配置与完整清单不一致")
	}
	if tx.Format == 4 {
		ca := tx.Changes[3]
		oldExists, oldCA := loadBalanceCAState(old)
		nextExists, nextCA := loadBalanceCAState(next)
		if ca.Path != s.loadBalanceCAPath(tx.Domain) || !oldExists || !nextExists || !ca.OldExists || !ca.NextExists || ca.OldMode != 0600 || ca.NextMode != 0600 ||
			!bytes.Equal(ca.OldData, oldCA) || !bytes.Equal(ca.NextData, nextCA) || !bytes.Equal(oldCA, nextCA) {
			return errors.New("自动流量不得改换或遗漏 HTTPS 后端 CA")
		}
	}
	return nil
}

// Called under the shared configuration lock, after all network probes and
// all-entry revision/state checks. The same durable recovery path verifies
// EVERY old/new file before the first restore, then confirms native generation.
func (s *Service) commitLoadBalanceRouting(ctx context.Context, old, next loadBalanceEntry, state loadBalanceHTTPState) error {
	if s.loadBalanceHealthVersion() != "1.7.0" {
		return errors.New("自动流量需要已安装负载均衡 v1.7.0，不隐式升级授权")
	}
	unlock, err := s.lockRuntimeUse()
	if err != nil {
		return err
	}
	defer unlock()
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	for _, path := range []string{s.loadBalancePendingPath(), s.wafPendingPath()} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("存在未完成配置事务，未自动改变流量")
		}
	}
	current, present, err := s.readLoadBalanceEntry(old.Domain)
	if err != nil || !present || loadBalanceFingerprint(current) != loadBalanceFingerprint(old) {
		return errors.New("自动流量提交前入口改变，保留旧检查结果")
	}
	conf, meta := s.loadBalancePaths(old.Domain)
	healthPath := s.loadBalanceHealthPath(old.Domain)
	for _, dir := range []string{filepath.Dir(conf), filepath.Dir(meta), filepath.Dir(healthPath), filepath.Dir(s.loadBalancePendingPath())} {
		if err = s.wafOwnedDirectory(dir, true); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Dir(s.loadBalancePendingPath()))
	if err != nil || len(entries) >= 512 {
		return errors.New("流量恢复事务达到 512 份或不可读取，保留原流量与证据")
	}
	rendered, err := s.renderLoadBalanceEntry(next)
	if err != nil {
		return err
	}
	metadata, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	metadata = append(metadata, '\n')
	state.Fingerprint = loadBalanceFingerprint(next)
	health, err := json.Marshal(state)
	if err != nil {
		return err
	}
	health = append(health, '\n')
	changes := []wafConfigChange{}
	for _, v := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{conf, []byte(rendered), 0644}, {meta, metadata, 0600}, {healthPath, health, 0600}} {
		before, err := backupFile(v.path)
		if err != nil {
			return err
		}
		if !before.existed {
			before.mode = 0
		}
		changes = append(changes, wafConfigChange{Path: v.path, OldExists: before.existed, OldData: before.data, OldMode: before.mode, NextExists: true, NextData: v.data, NextMode: v.mode})
	}
	format := 3
	if next.BackendTLS != nil {
		if err = s.verifyLoadBalanceCA(old); err != nil {
			return err
		}
		_, ca := loadBalanceCAState(next)
		changes = append(changes, wafConfigChange{Path: s.loadBalanceCAPath(old.Domain), OldExists: true, OldData: ca, OldMode: 0600, NextExists: true, NextData: ca, NextMode: 0600})
		format = 4
	}
	tx := loadBalanceTransaction{Format: format, ID: core.ID(), Domain: old.Domain, State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
	for _, c := range changes {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
		match, err := s.wafCurrentMatches(c, false)
		if err != nil || !match {
			return errors.New("自动流量快照出现外部修改，未开始写入")
		}
	}
	if err = s.writeLoadBalanceTransaction(filepath.Join(filepath.Dir(s.loadBalancePendingPath()), tx.ID+".json"), tx); err != nil {
		return err
	}
	if err = s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), tx); err != nil {
		return err
	}
	rollback := func(cause error) error {
		recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if restore := s.recoverLoadBalanceBeforeMutation(recovery, nginx); restore != nil {
			return fmt.Errorf("%v；自动流量恢复未确认，保留完整事务：%w", cause, restore)
		}
		return fmt.Errorf("%v；原入口、运行状态与检查记录已恢复", cause)
	}
	for _, c := range changes {
		match, err := s.wafCurrentMatches(c, false)
		if err != nil || !match {
			return rollback(errors.New("自动流量写入前冲突"))
		}
		if err = wafApplyChange(c, true); err != nil {
			return rollback(err)
		}
	}
	if err = s.reloadLoadBalance(ctx, nginx); err != nil {
		return rollback(err)
	}
	if err = s.verifyLoadBalanceLive(ctx, next); err != nil {
		return rollback(err)
	}
	tx.State = "committed"
	if err = s.finishLoadBalanceTransaction(tx); err != nil {
		return fmt.Errorf("流量已生效但归档未完成，保留原事务并先核对：%w", err)
	}
	return nil
}

func loadBalanceNodeDown(v loadBalanceEntry, address string) bool {
	if v.Routing == nil {
		return false
	}
	i := sort.SearchStrings(v.Routing.Down, address)
	return i < len(v.Routing.Down) && v.Routing.Down[i] == address
}

// No last-success shortcut: a failed node remains out until the full recovery
// threshold changes its durable state to healthy. Unknown initial nodes remain
// admitted; if all nodes reach unhealthy, all are down (no silent fail-open).
func loadBalanceRoutingNext(v loadBalanceEntry, state loadBalanceHTTPState) (loadBalanceEntry, bool, error) {
	if !core.LoadBalanceAutomaticTraffic(v.HealthCheck) || validateLoadBalanceRouting(v) != nil ||
		state.Domain != v.Domain || state.Revision != v.Revision || state.Fingerprint != loadBalanceFingerprint(v) || len(state.Nodes) != len(v.Nodes) {
		return v, false, errors.New("自动流量只能采用当前显式策略的完整健康记录")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return v, false, err
	}
	decoded, err := decodeLoadBalanceHTTPState(v, raw, time.Now().UTC())
	if err != nil || decoded == nil {
		return v, false, errors.New("完整健康记录未通过当前身份、阈值或时间核对")
	}
	down := []string{}
	for i, node := range state.Nodes {
		if node.Address != v.Nodes[i].Address || !lbHealthStateName(node.State) {
			return v, false, errors.New("健康节点身份或判定状态不符合当前入口")
		}
		if node.State == "unhealthy" || node.State == "unknown" && loadBalanceNodeDown(v, node.Address) {
			down = append(down, node.Address)
		}
	}
	sort.Strings(down)
	a, _ := json.Marshal(down)
	b, _ := json.Marshal(v.Routing.Down)
	if string(a) == string(b) {
		return v, false, nil
	}
	if v.Routing.Sequence >= (1<<60)-1 {
		return v, false, errors.New("自动流量运行序号达到上限，保留原入口")
	}
	v.Routing = &loadBalanceRouting{Sequence: v.Routing.Sequence + 1, Down: down}
	return v, true, nil
}
