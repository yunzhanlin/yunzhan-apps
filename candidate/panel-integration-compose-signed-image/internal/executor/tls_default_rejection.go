package executor

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"os"
	"syscall"
	"time"
)

// Ubuntu 22.04's Nginx 1.18 cannot reject a TLS handshake. Its installer uses
// one root-owned, dedicated invalid certificate and return 444 instead. Never
// accept another certificate or even one byte of HTTP response as rejection.
func legacyDefaultTLSRejected(conn net.Conn, domain string) bool {
	if runtimecatalog.HostPlatform() != "ubuntu-22.04" {
		return false
	}
	const path = "/etc/panel/default-ssl.crt"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName != "default.invalid" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "default.invalid" || len(cert.IPAddresses) != 0 {
		return false
	}
	return proveEmptyDefaultTLS(conn, domain, cert.Raw)
}

func proveEmptyDefaultTLS(conn net.Conn, domain string, trustedDER []byte) bool {
	secure, ok := conn.(*tls.Conn)
	if !ok || !core.ValidDomain(domain) || len(trustedDER) == 0 {
		return false
	}
	peers := secure.ConnectionState().PeerCertificates
	if len(peers) != 1 || !bytes.Equal(peers[0].Raw, trustedDER) {
		return false
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return false
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", domain); err != nil {
		return false
	}
	var first [1]byte
	n, err := conn.Read(first[:])
	return n == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
}
