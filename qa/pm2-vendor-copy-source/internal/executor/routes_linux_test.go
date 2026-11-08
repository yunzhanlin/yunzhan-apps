//go:build linux

package executor

import (
	"net/http/httptest"
	"testing"
)

func TestLinuxExecutorRoutesRegisterAndHealthIsReady(t *testing.T) {
	service := New(Config{})
	handler := service.Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/v1/health", nil))
	if response.Code != 200 {
		t.Fatal("executor health is not ready", response.Code)
	}
}
