package executor

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func buildJobsFor(cpu int, available uint64) int {
	if cpu < 1 {
		cpu = 1
	}
	if cpu > 4 {
		cpu = 4
	}
	// Leave capacity for the running panel, websites and database services.
	if available > 0 {
		jobs := 1
		if available > 512<<20 {
			jobs = int((available - (512 << 20)) / (512 << 20))
			if jobs < 1 {
				jobs = 1
			}
		}
		if jobs < cpu {
			cpu = jobs
		}
	}
	return cpu
}

func memoryAvailable(contents []byte) uint64 {
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			kb, err := strconv.ParseUint(fields[1], 10, 52)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

func runtimeBuildJobs() int {
	info, _ := os.ReadFile("/proc/meminfo")
	available := memoryAvailable(info)
	limited, verified := compilerCurrentCgroupAvailable()
	if !verified {
		return 1
	}
	if limited > 0 && (available == 0 || limited < available) {
		available = limited
	}
	if available == 0 {
		return 1
	}
	return buildJobsFor(runtime.NumCPU(), available)
}
