package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const platformMaintenanceFleetLimit = 8

// Shared across concurrent requests so separate browser sessions cannot
// multiply the configured remote request budget.
var platformMaintenanceFleetSlots = make(chan struct{}, 3)

type platformMaintenanceFleetResult struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Outcome   string `json:"outcome,omitempty"`
}

func decodePlatformMaintenanceFleet(raw []byte) ([]platformMaintenanceRemoteInput, error) {
	invalid := errors.New("批量检查须包含 2–8 个不同的 HTTPS 面板，每台使用独立授权、原计划和原请求 ID")
	var input struct {
		Targets []json.RawMessage `json:"targets"`
	}
	if !wafInventoryJSONShape(raw, []string{"targets"}) || json.Unmarshal(raw, &input) != nil ||
		len(input.Targets) < 2 || len(input.Targets) > platformMaintenanceFleetLimit {
		return nil, invalid
	}
	origins, ids, tokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	targets := make([]platformMaintenanceRemoteInput, 0, len(input.Targets))
	for _, row := range input.Targets {
		var target platformMaintenanceRemoteInput
		var shape struct{ Operation json.RawMessage }
		if len(row) > 4096 || !wafInventoryJSONShape(row, []string{"url", "token", "actor_id", "operation"}) ||
			json.Unmarshal(row, &target) != nil || json.Unmarshal(row, &shape) != nil ||
			validatePlatformMaintenancePeer(target.URL, target.Token) != nil || !ValidID(target.ActorID) {
			return nil, invalid
		}
		op, err := DecodePlatformMaintenanceInput(shape.Operation)
		if err != nil || op.Command != "nginx-check" {
			return nil, invalid
		}
		parsed, _ := url.Parse(target.URL)
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return nil, invalid
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.Unmap().String()
		}
		key := host + "\x00" + strconv.Itoa(number)
		if host == "" || origins[key] || ids[op.RequestID] || tokens[target.Token] {
			return nil, invalid
		}
		origins[key], ids[op.RequestID], tokens[target.Token] = true, true, true
		target.Operation = op
		targets = append(targets, target)
	}
	return targets, nil
}

func (s *Store) claimPlatformMaintenanceFleetCheck(ctx context.Context, actor, id, binding string) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = platformMaintenanceCommandAllowed(ctx, tx, actor, "nginx-check"); err != nil {
		return false, err
	}
	row, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at)
SELECT ?,'platform.maintenance.remote.fleet.submit',?,?,? WHERE NOT EXISTS
(SELECT 1 FROM audit_logs WHERE action IN ('platform.maintenance.remote.submit','platform.maintenance.remote.fleet.submit') AND target=?)`, actor, id, binding, Now(), id)
	if err != nil {
		return false, err
	}
	n, err := row.RowsAffected()
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}

func (a *Server) platformMaintenanceFleetCheck(ctx context.Context, client *http.Client, actor string, target platformMaintenanceRemoteInput) platformMaintenanceFleetResult {
	op := target.Operation
	result := platformMaintenanceFleetResult{RequestID: op.RequestID, State: "not_dispatched"}
	var reserved bool
	err := a.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs
WHERE action IN ('platform.maintenance.remote.submit','platform.maintenance.remote.fleet.submit') AND target=?)`, op.RequestID).Scan(&reserved)
	if err != nil || reserved {
		result.State = "needs_attention"
		return result
	}
	select {
	case platformMaintenanceFleetSlots <- struct{}{}:
		defer func() { <-platformMaintenanceFleetSlots }()
	case <-ctx.Done():
		return result
	}
	wire, status, err := platformMaintenancePeerCall(ctx, client, target.URL, target.Token, "GET", "/api/platform-maintenance/plan", nil)
	if err != nil || status != 200 {
		return result
	}
	plan, err := decodePlatformMaintenanceRemotePlan(wire, target.Token)
	if err != nil || plan.ActorID != target.ActorID || plan.Plan.SHA != op.ExpectedPlanSHA || !containsString(plan.AllowedCommands, op.Command) {
		return result
	}
	req := PlatformMaintenanceNativeRequest{Format: 1, GrantID: plan.GrantID, ActorID: plan.ActorID, Input: op}
	binding := Hash(strings.TrimRight(target.URL, "/") + "\x00" + PlatformMaintenanceRequestSHA(req))
	claimed, err := a.Store.claimPlatformMaintenanceFleetCheck(ctx, actor, op.RequestID, binding)
	if err != nil {
		// A failed commit can be ambiguous. Conservatively retain the original
		// identity for read-only reconciliation rather than authorizing a retry.
		result.State = "needs_attention"
		return result
	}
	if !claimed {
		result.State = "needs_attention"
		return result
	}
	body, _ := json.Marshal(op)
	wire, status, err = platformMaintenancePeerCall(ctx, client, target.URL, target.Token, "POST", "/api/platform-maintenance/commands", body)
	result.State = "needs_attention"
	if err != nil || status != 200 {
		return result
	}
	receipt, err := DecodePlatformMaintenanceRecord(wire, req)
	if err != nil || receipt.State == "started" {
		return result
	}
	if _, err = a.Store.DB.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.remote.observed',?,?,?)", actor, op.RequestID, Hash(string(wire)), Now()); err != nil {
		return result
	}
	result.State, result.Outcome = receipt.State, receipt.Outcome
	return result
}

func (s *Store) platformMaintenanceFleetReceipt(ctx context.Context) bool {
	var version, digest string
	err := s.DB.QueryRowContext(ctx, "SELECT version,sha256 FROM app_registry_receipts WHERE app_id='platform-ops' AND scope='platform-ops'").Scan(&version, &digest)
	return err == nil && version == PlatformMaintenanceFleetAppVersion && platformMaintenanceSHA.MatchString(digest)
}

func (a *Server) platformMaintenanceFleetCheckHandler(w http.ResponseWriter, r *http.Request, u identity) {
	var m struct {
		Status SoftwareAppStatus `json:"status"`
	}
	if a.Executor.Call(r.Context(), "GET", "/v1/app-modules/platform-ops", nil, &m) != nil ||
		!knownInstalledAppModule("platform-ops", m.Status) || m.Status.Version != PlatformMaintenanceFleetAppVersion ||
		!ValidID(m.Status.InstallationID) ||
		!a.Store.platformMaintenanceFleetReceipt(r.Context()) {
		fail(w, 409, "请先通过签名应用商店更新平台运维至 1.3.1")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, (platformMaintenanceFleetLimit*4096)+128))
	if err != nil {
		fail(w, 400, "批量检查请求读取失败或超限")
		return
	}
	targets, err := decodePlatformMaintenanceFleet(raw)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	client := platformMaintenanceClient()
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	results := make([]platformMaintenanceFleetResult, len(targets))
	var workers sync.WaitGroup
	for i, target := range targets {
		workers.Go(func() { results[i] = a.platformMaintenanceFleetCheck(ctx, client, u.ID, target) })
	}
	workers.Wait()
	allOK := true
	for _, item := range results {
		allOK = allOK && item.State == "completed"
	}
	send(w, 200, map[string]any{"results": results, "all_succeeded": allOK})
}
