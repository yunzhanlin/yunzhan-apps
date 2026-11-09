package executor

import "testing"

func TestBuildJobsRespectSmallServers(t *testing.T) {
	for _, x := range []struct {
		cpu  int
		free uint64
		want int
	}{{1, 8 << 30, 1}, {16, 8 << 30, 4}, {4, 512 << 20, 1}, {8, 1 << 30, 1}, {8, 2 << 30, 3}, {0, 0, 1}} {
		if got := buildJobsFor(x.cpu, x.free); got != x.want {
			t.Fatalf("%+v: got %d", x, got)
		}
	}
	if got := memoryAvailable([]byte("MemTotal: 1000000 kB\nMemAvailable: 524288 kB\n")); got != 512<<20 {
		t.Fatal(got)
	}
}
