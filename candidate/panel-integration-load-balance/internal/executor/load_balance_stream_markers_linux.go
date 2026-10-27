//go:build linux

package executor

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Configuration selector evidence ONLY, never backend readiness or forwarded
// business traffic. Every GET targets a verified owned loopback marker server;
// it cannot select a URL/path, follow a redirect, use environment proxies,
// send a cookie or cause a customer's application request to be retried.
func verifyLoadBalanceStreamConfigurationMarkers(ctx context.Context, service *loadBalanceStreamServiceObservation, entries []loadbalancestream.Entry) error {
	if service == nil || service.current(ctx) != nil {
		return loadbalancestream.ErrService
	}
	runtime, err := loadbalancestream.RenderRuntime(entries, loadbalancestream.ServiceRuntimePrefix, loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil || runtime.SHA256 != service.plan.Current.SHA256 {
		return loadbalancestream.ErrService
	}
	if _, err := observeLoadBalanceStreamOwnedListeners(ctx, service, entries); err != nil {
		return loadbalancestream.ErrService
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 2048, ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, entry := range entries {
		if entry.Removed {
			continue
		}
		if service.current(bounded) != nil {
			return loadbalancestream.ErrService
		}
		req, err := http.NewRequestWithContext(bounded, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(entry.ProbePort)+loadbalancestream.ProbePath(entry.Name), nil)
		if err != nil {
			return loadbalancestream.ErrService
		}
		req.Host = entry.Name
		response, err := client.Do(req)
		if err != nil {
			return loadbalancestream.ErrService
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || len(body) > 256 || string(body) != loadbalancestream.Fingerprint(entry) {
			return loadbalancestream.ErrService
		}
	}
	if service.current(bounded) != nil {
		return loadbalancestream.ErrService
	}
	return nil
}
