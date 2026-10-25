package runtimecatalog

import "runtime"

// Digests are pinned from each release's official SHASUMS256.txt.
func NodeForArch(arch string) []Release {
	switch arch {
	case "arm64":
		return []Release{
			{"node-22.23.2", "node", "22.23.2", "22", "lts", "https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-arm64.tar.gz", "013b59cfd2819703a6f4a14ab891fc46fc2a4e3f5bcd92de3fb4929b43e35b30", "Node.js 官方二进制 · 官方 SHA-256 清单"},
			{"node-24.21.0", "node", "24.21.0", "24", "lts", "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-arm64.tar.gz", "724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5", "Node.js 官方二进制 · 官方 SHA-256 清单"},
		}
	default:
		return []Release{
			{"node-22.23.2", "node", "22.23.2", "22", "lts", "https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.gz", "b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a", "Node.js 官方二进制 · 官方 SHA-256 清单"},
			{"node-24.21.0", "node", "24.21.0", "24", "lts", "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.gz", "6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff", "Node.js 官方二进制 · 官方 SHA-256 清单"},
		}
	}
}

func Node() []Release { return NodeForArch(runtime.GOARCH) }
