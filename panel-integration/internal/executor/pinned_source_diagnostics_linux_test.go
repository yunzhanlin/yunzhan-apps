//go:build linux

package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestPinnedSourceTransportDiagnosticNeverReturnsRequestOrProxySecrets(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"dns-resolution", &net.DNSError{Err: "proxy_password=do-not-disclose", Name: "secret.internal.example"}},
		{"permission-denied", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EPERM}},
		{"read-only-filesystem", syscall.EROFS},
		{"network-unreachable", syscall.ENETUNREACH},
		{"connection-refused", syscall.ECONNREFUSED},
		{"connection-reset", syscall.ECONNRESET},
		{"unexpected-eof", io.ErrUnexpectedEOF},
		{"tls-protocol", tls.RecordHeaderError{Msg: "credential=do-not-disclose"}},
		{"other-transport", errors.New("Bearer do-not-disclose")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := pinnedSourceTransportFailure(&url.Error{Op: "Get", URL: "https://user:password@cdn.example/archive?signature=do-not-disclose", Err: tc.err})
			if !errors.Is(err, errWAFSourceTransport) || !wafSourceRetryable(err) || !strings.Contains(err.Error(), "故障类别="+tc.name+"；") {
				t.Fatal("closed transport classification or retry contract failed", err)
			}
			for _, secret := range []string{"do-not-disclose", "signature", "password", "Bearer", "secret.internal", "https://"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("transport diagnostic leaked a request/proxy credential", secret)
				}
			}
		})
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := pinnedSourceTransportFailure(&url.Error{Op: "Get", URL: "https://cdn.example/?signature=do-not-disclose", Err: cause})
		if !errors.Is(err, cause) || errors.Is(err, errWAFSourceTransport) || wafSourceRetryable(err) || strings.Contains(err.Error(), "signature") {
			t.Fatal("cancel/deadline identity was lost or credentials leaked", err)
		}
	}
}
