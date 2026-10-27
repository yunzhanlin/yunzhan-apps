package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// Core-only peer models. Error text, including an alleged committed response,
// cannot authorize completion or a second dispatch to the native service.
func TestLoadBalanceStreamCoreContractModelRetainsBoundedFailureStage(t *testing.T) {
	for _, reason := range []string{
		"TCP/UDP 安装阶段[系统身份源]: 当前身份源尚未支持",
		"\x00\r\n 原生调用\t被拒绝 \x1b",
		strings.Repeat("原生错误🙂", 1024),
		"",
	} {
		t.Run(reason[:min(len(reason), 24)], func(t *testing.T) {
			s, _, j := streamInstallCoreFixtureJob(t, "update")
			calls := 0
			var originalRequest string
			if err := s.DB.QueryRow("SELECT request_sha256 FROM load_balance_stream_install_requests WHERE job_id=?", j.ID).Scan(&originalRequest); err != nil {
				t.Fatal(err)
			}
			e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/load-balance-stream/install-jobs" {
					t.Fatal("unexpected native route")
				}
				body, err := json.Marshal(struct {
					LoadBalanceStreamInstallResult
					Error string `json:"error"`
				}{streamInstallCoreModelResult(j), reason})
				if err != nil {
					t.Fatal(err)
				}
				return streamInstallCoreResponse(http.StatusConflict, body), nil
			})}}
			runLoadBalanceStreamInstallJobWithMetadata(context.Background(), s, e, j, streamInstallCoreModelMetadata)
			var detail, payload, request string
			if err := s.DB.QueryRow("SELECT error,payload FROM runtime_jobs WHERE id=?", j.ID).Scan(&detail, &payload); err != nil {
				t.Fatal(err)
			}
			if err := s.DB.QueryRow("SELECT request_sha256 FROM load_balance_stream_install_requests WHERE job_id=?", j.ID).Scan(&request); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || streamInstallCoreState(t, s, j) != "needs_attention" || payload != j.Payload || request != originalRequest {
				t.Fatal("native failure changed original authority, completed or repeated dispatch")
			}
			if !utf8.ValidString(detail) || len(detail) > 1024 || strings.ContainsAny(detail, "\x00\r\n\t\x1b") || !strings.Contains(detail, "不重新派发") {
				t.Fatal("unbounded, malformed or misleading failure detail", detail)
			}
			if strings.HasPrefix(reason, "TCP/UDP 安装阶段") && !strings.Contains(detail, "安装阶段[系统身份源]") {
				t.Fatal("actual native rejection stage lost", detail)
			}
		})
	}
}
