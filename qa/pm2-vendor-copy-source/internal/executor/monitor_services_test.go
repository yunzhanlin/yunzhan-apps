package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMonitorServicesUsesOnlyMappedUnits(t *testing.T) {
	called := false
	service := New(Config{Run: func(_ context.Context, name string, args ...string) (string, error) {
		called = true
		if name != "/usr/bin/systemctl" || args[len(args)-2] != "nginx.service" || args[len(args)-1] != "panel-mysql@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service" {
			t.Fatal("unexpected command", name, args)
		}
		return "Id=nginx.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\nId=panel-mysql@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n", nil
	}})
	mux := http.NewServeMux()
	service.monitorServiceRoutes(mux)
	body := `{"services":[{"kind":"nginx","resource_id":"nginx"},{"kind":"mysql","resource_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("POST", "/v1/monitor/services", strings.NewReader(body)))
	if response.Code != 200 || !called {
		t.Fatal(response.Code, response.Body.String())
	}
	var result struct {
		Services []monitoredServiceResult `json:"services"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Services) != 2 || result.Services[0].ActualState != "active" || result.Services[1].ActualState != "inactive" {
		t.Fatal("unexpected service response", response.Body.String())
	}
}

func TestMonitorServicesRejectsUnitInjection(t *testing.T) {
	service := New(Config{Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("invalid service reached command runner")
		return "", nil
	}})
	mux := http.NewServeMux()
	service.monitorServiceRoutes(mux)
	response := httptest.NewRecorder()
	body := `{"services":[{"kind":"php","resource_id":"../../ssh"}]}`
	mux.ServeHTTP(response, httptest.NewRequest("POST", "/v1/monitor/services", strings.NewReader(body)))
	if response.Code != 400 {
		t.Fatal("invalid unit accepted", response.Code, response.Body.String())
	}
}
