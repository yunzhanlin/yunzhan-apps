// startguard is deliberately separate from the panel/executor payload.
// No daemon, database, recovery worker, socket or user constructor runs here.
package main

import (
	"fmt"
	"os"

	"local/panel/internal/upgradeguard"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "program startup interlock requires one fixed service name")
		os.Exit(255)
	}
	if err := upgradeguard.CheckServiceStartup(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "program startup interlock refused:", err)
		os.Exit(255)
	}
}
