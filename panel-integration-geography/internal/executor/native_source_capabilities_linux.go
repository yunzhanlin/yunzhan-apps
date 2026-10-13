//go:build linux

package executor

import "os"

func verifyNginxNativeWorkerCapabilities() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	return validateNginxNativeWorkerCapabilities(data)
}
