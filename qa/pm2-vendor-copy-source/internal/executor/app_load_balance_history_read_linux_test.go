//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestLoadBalancePrivateExactReadRetainsLimitsAndPostReadIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "own-private.json")
	for _, size := range []int{0, 1, 32 << 10, 256 << 10} {
		want := bytes.Repeat([]byte("x"), size)
		if err := os.WriteFile(p, want, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := loadBalancePrivateRead(p, 256<<10)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("exact original bytes lost", err, size)
		}
	}
	if _, err := loadBalancePrivateRead(p, (256<<10)-1); err == nil {
		t.Fatal("original byte limit weakened")
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBalancePrivateRead(p, 256<<10); err == nil {
		t.Fatal("private mode weakened")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(p), "own-link.json")
	if err := os.Link(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBalancePrivateRead(p, 256<<10); err == nil {
		t.Fatal("single-link identity weakened")
	}
	a := unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFREG | 0600, Nlink: 1, Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid()), Size: 32, Mtim: unix.Timespec{Sec: 3}, Ctim: unix.Timespec{Sec: 4}}
	for _, edit := range []func(*unix.Stat_t){
		func(b *unix.Stat_t) { b.Dev++ }, func(b *unix.Stat_t) { b.Ino++ }, func(b *unix.Stat_t) { b.Mode = unix.S_IFREG | 0644 }, func(b *unix.Stat_t) { b.Nlink++ },
		func(b *unix.Stat_t) { b.Uid++ }, func(b *unix.Stat_t) { b.Gid++ }, func(b *unix.Stat_t) { b.Size++ }, func(b *unix.Stat_t) { b.Mtim.Nsec++ }, func(b *unix.Stat_t) { b.Ctim.Nsec++ },
	} {
		b := a
		edit(&b)
		if loadBalancePrivateStatUnchanged(a, b) {
			t.Fatal("post-read security identity change accepted")
		}
	}
	b := a
	b.Atim.Sec++
	if !loadBalancePrivateStatUnchanged(a, b) {
		t.Fatal("legitimate read access-time change rejected")
	}
}

func TestLoadBalanceHistoryParallelReadersRemainBoundedAndFailClosed(t *testing.T) {
	records := make([]loadBalanceHistoryRead, 8)
	for i := range records {
		records[i] = loadBalanceHistoryRead{id: core.ID(), bytes: 32}
	}
	started, release := make(chan struct{}, 8), make(chan struct{})
	var active, maximum atomic.Int32
	type result struct {
		rows []loadBalanceHistoryRow
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rows, err := loadBalanceHistoryReadRows(context.Background(), records, func(_ string, id string, _ bool) (loadBalanceHistoryRow, error) {
			n := active.Add(1)
			for previous := maximum.Load(); n > previous && !maximum.CompareAndSwap(previous, n); previous = maximum.Load() {
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return loadBalanceHistoryRow{ID: id, Bytes: 32}, nil
		})
		done <- result{rows, err}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("bounded readers did not start")
		}
	}
	if maximum.Load() != 2 {
		close(release)
		t.Fatal("reader count not bounded at two")
	}
	close(release)
	got := <-done
	if got.err != nil || len(got.rows) != len(records) || maximum.Load() > 2 || active.Load() != 0 {
		t.Fatal("full inventory or worker bound lost", got.err)
	}
	for i, row := range got.rows {
		if row.ID != records[i].id {
			t.Fatal("row identity/order lost")
		}
	}
	for _, mode := range []string{"invalid", "size", "cancelled"} {
		ctx, cancel := context.WithCancel(context.Background())
		if mode == "cancelled" {
			cancel()
		}
		rows, err := loadBalanceHistoryReadRows(ctx, records, func(_ string, id string, _ bool) (loadBalanceHistoryRow, error) {
			if mode == "invalid" {
				return loadBalanceHistoryRow{}, errors.New("owned invalid original")
			}
			return loadBalanceHistoryRow{ID: id, Bytes: 31}, nil
		})
		cancel()
		if err == nil || rows != nil {
			t.Fatal("invalid, changed or cancelled inventory became partial success", mode)
		}
	}
}

func TestLoadBalanceHistoryWhitespaceOptimizationPreservesWholeDigestAndStrictJSON(t *testing.T) {
	s, tx, p, original := lbHistoryFixture(t)
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range [][]byte{[]byte(" \t\r\n"), bytes.Repeat([]byte(" "), (256<<10)-len(raw))} {
		data := append(append([]byte(nil), raw...), suffix...)
		if err := atomicWrite(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		row, err := s.loadBalanceHistoryRecord(p, tx.ID, false)
		if err != nil || row.Bytes != int64(len(data)) || row.SHA != core.Hash(string(data)) {
			t.Fatal("whole raw byte identity or contract lost", err)
		}
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("reader changed original evidence", err)
		}
	}
	for _, suffix := range []string{"\v", "\f", "\u00a0", "\u2003", " {}", " []", " null", " x"} {
		data := append(append([]byte(nil), raw...), []byte(suffix)...)
		if err := atomicWrite(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.loadBalanceHistoryRecord(p, tx.ID, false); err == nil {
			t.Fatal("invalid JSON suffix accepted", suffix)
		}
		got, _ := os.ReadFile(p)
		if !bytes.Equal(got, data) {
			t.Fatal("invalid evidence changed")
		}
	}
	unknown := bytes.Replace(raw, []byte("\"id\":"), []byte("\"unreviewed\":true,\"id\":"), 1)
	if err := atomicWrite(p, unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadBalanceHistoryRecord(p, tx.ID, false); err == nil {
		t.Fatal("unknown JSON extension accepted")
	}
	if err := atomicWrite(p, original, 0600); err != nil {
		t.Fatal(err)
	}
}
