//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWAFSameUIDFailureDiagnosticsKeepFixedBoundsAndHidePrivateOutput(t *testing.T) {
	private := errors.New("private-secret /var/lib/private/request-body")
	for _, c := range []struct {
		step              string
		runErr, ctxErr    error
		truncated, stderr bool
		reason            string
	}{
		{"executable", private, nil, false, false, "子进程未成功退出"},
		{"descriptor-count", private, nil, false, true, "子进程报告读取异常"},
		{"socket-inodes", private, context.DeadlineExceeded, false, false, "原有读取期限已到"},
		{"socket-inodes", private, context.Canceled, false, false, "原读取上下文已取消"},
		{"socket-inodes", private, nil, true, true, "有界输出超限"},
		{"socket-inodes", nil, nil, false, false, "读取结果无法核对"},
	} {
		err := wafSameUIDReadFailure("sockets", c.step, c.runErr, c.ctxErr, c.truncated, c.stderr)
		if err == nil || !strings.Contains(err.Error(), c.reason) || !strings.Contains(err.Error(), "未据此认定监听已关闭") || strings.Contains(err.Error(), "private") || errors.Is(err, private) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("diagnostic changed fail-closed identity semantics or exposed private child output", err)
		}
	}
	for _, op := range []string{"private-secret", "exe"} {
		err := wafSameUIDReadFailure(op, "private-secret", private, nil, false, true)
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("nonfixed diagnostic step exposed", err)
		}
	}
}

func TestWAFSameUIDNumericReadersAreClosed(t *testing.T) {
	dev, ino, err := wafSameUIDExecutableInode([]byte("8388625:123456\n"))
	if err != nil || dev != 8388625 || ino != 123456 {
		t.Fatal("canonical executable inode refused", err)
	}
	for _, value := range []string{"", "1:2", "1:2\nextra", "1:2\n\n", "1:2\r\n", "1:2\x00\n", "01:2\n", "1:02\n", "0:2\n", "1:0\n", "-1:2\n", "1:+2\n", "1:2:3\n", "18446744073709551616:2\n", strings.Repeat("1", 129) + ":2\n"} {
		if _, _, err := wafSameUIDExecutableInode([]byte(value)); err == nil {
			t.Fatal("noncanonical inode accepted")
		}
	}
	for _, value := range []string{"", "socket:[7]\n", "socket:[7]\nsocket:[7]\nsocket:[8]\n"} {
		if _, err := wafSameUIDSocketInodes([]byte(value)); err != nil {
			t.Fatal("valid socket list refused", err)
		}
	}
	for _, value := range []string{"socket:[7]", "socket:[0]\n", "socket:[07]\n", "socket:[+7]\n", "socket:[-7]\n", "socket:[18446744073709551616]\n", "socket:[7]\n\n", "socket:[7]\r\n", "socket:[7]\x00\n", "/private/request/body\n", "socket:[7]\n/private/request/body\n", strings.Repeat("socket:[7]\n", 65537)} {
		if _, err := wafSameUIDSocketInodes([]byte(value)); err == nil {
			t.Fatal("non-numeric or oversized socket output accepted")
		}
	}
	for _, value := range []string{"", "0\n", "0\n1\n4294967295\n"} {
		if err := wafSameUIDDescriptorNames([]byte(value)); err != nil {
			t.Fatal("valid descriptor names refused", err)
		}
	}
	for _, value := range []string{"0", "0\n0\n", "01\n", "-1\n", "4294967296\n", "1\r\n", "1\x00\n", "private\n", strings.Repeat("1\n", 65537)} {
		if err := wafSameUIDDescriptorNames([]byte(value)); err == nil {
			t.Fatal("bad descriptor names accepted")
		}
	}
	var all strings.Builder
	for i := 0; i < 65536; i++ {
		fmt.Fprintf(&all, "%d\n", i)
	}
	if err := wafSameUIDDescriptorNames([]byte(all.String())); err != nil {
		t.Fatal("exact original descriptor budget refused", err)
	}
}

func TestWAFSameUIDOnlyFixedWorkerIdentity(t *testing.T) {
	valid := "Name:\tnginx\nPPid:\t123\nUid:\t33\t33\t33\t33\n"
	if err := wafSameUIDWorkerIdentity([]byte(valid), 33, 123); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "PPid:123\n", "PPid:123\nUid:33 33 33\n", "PPid:123\nUid:0 33 33 33\n", "PPid:123\nUid:34 34 34 34\n", "PPid:124\nUid:33 33 33 33\n", "PPid:123\nUid:033 033 033 033\n", valid + "PPid:123\n", valid + "Uid:33 33 33 33\n"} {
		if err := wafSameUIDWorkerIdentity([]byte(value), 33, 123); err == nil {
			t.Fatal("unexpected identity accepted")
		}
	}
	for _, tc := range []struct {
		root, operation string
		process         wafReloadProcess
	}{
		{"/tmp/proc", "exe", wafReloadProcess{PID: 10, Parent: 2, Start: 3}},
		{"/proc", "environ", wafReloadProcess{PID: 10, Parent: 2, Start: 3}},
		{"/proc", "exe", wafReloadProcess{PID: 1, Parent: 2, Start: 3}},
		{"/proc", "sockets", wafReloadProcess{PID: 10, Parent: 1, Start: 3}},
		{"/proc", "exe", wafReloadProcess{PID: 10, Parent: 2}},
	} {
		if _, err := wafSameUIDWorkerRead(context.Background(), tc.root, "/usr/sbin/nginx", tc.process, tc.operation); err == nil {
			t.Fatal("arbitrary reader request accepted")
		}
	}
}
