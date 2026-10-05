package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// fastCGIProbe requests a task-owned, temporary PHP file via the candidate
// Unix socket before Nginx points any public traffic at that pool.
func fastCGIProbe(ctx context.Context, socket, script, expected string) error {
	var last error
	for n := 0; n < 15; n++ {
		last = fastCGIOnce(ctx, socket, script, expected)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return last
}
func fastCGIOnce(ctx context.Context, socket, script, expected string) error {
	conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	write := func(kind byte, b []byte) error {
		if len(b) > 65535 {
			return errors.New("FastCGI request too large")
		}
		header := []byte{1, kind, 0, 1, byte(len(b) >> 8), byte(len(b)), 0, 0}
		_, e := io.Copy(conn, bytes.NewReader(append(header, b...)))
		return e
	}
	if e = write(1, []byte{0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return e
	}
	var params bytes.Buffer
	length := func(n int) {
		if n < 128 {
			params.WriteByte(byte(n))
		} else {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(n)|0x80000000)
			params.Write(b)
		}
	}
	for _, p := range [][2]string{{"SCRIPT_FILENAME", script}, {"SCRIPT_NAME", "/panel-probe.php"}, {"REQUEST_METHOD", "GET"}, {"QUERY_STRING", ""}, {"SERVER_PROTOCOL", "HTTP/1.1"}, {"SERVER_NAME", "localhost"}, {"SERVER_PORT", "19101"}, {"REMOTE_ADDR", "127.0.0.1"}, {"GATEWAY_INTERFACE", "CGI/1.1"}} {
		length(len(p[0]))
		length(len(p[1]))
		params.WriteString(p[0])
		params.WriteString(p[1])
	}
	if e = write(4, params.Bytes()); e != nil {
		return e
	}
	if e = write(4, nil); e != nil {
		return e
	}
	if e = write(5, nil); e != nil {
		return e
	}
	var output bytes.Buffer
	for n := 0; n < 100; n++ {
		header := make([]byte, 8)
		if _, e = io.ReadFull(conn, header); e != nil {
			return e
		}
		if header[0] != 1 || header[2] != 0 || header[3] != 1 {
			return errors.New("invalid FastCGI response")
		}
		size := int(header[4])<<8 | int(header[5])
		data := make([]byte, size)
		if _, e = io.ReadFull(conn, data); e != nil {
			return e
		}
		if _, e = io.CopyN(io.Discard, conn, int64(header[6])); e != nil {
			return e
		}
		if header[1] == 6 {
			output.Write(data)
			if output.Len() > 65536 {
				return errors.New("PHP probe exceeded response limit")
			}
		}
		if header[1] == 3 {
			_, body, ok := strings.Cut(output.String(), "\r\n\r\n")
			if !ok || strings.TrimSpace(body) != expected {
				return fmt.Errorf("PHP 候选进程返回异常，期望版本 %s", expected)
			}
			return nil
		}
	}
	return errors.New("FastCGI response exceeded record limit")
}
