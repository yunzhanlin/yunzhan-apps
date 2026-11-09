//go:build !linux

package executor

func compilerCurrentCgroupAvailable() (uint64, bool) { return 0, false }
