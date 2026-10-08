//go:build !linux

package executor

import "os"

// Linux is the deployable executor. Host compilation does not claim Linux
// ownership preservation; the native Linux tests verify actual UID and GID.
func fileOwnerForInfo(os.FileInfo) (*fileOwner, error) { return nil, nil }
