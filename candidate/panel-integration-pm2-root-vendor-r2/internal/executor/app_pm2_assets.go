package executor

import _ "embed"

//go:embed pm2-assets/package.json
var pm2Package []byte

//go:embed pm2-assets/package-lock.json
var pm2Lock []byte

// Ubuntu 22.04's distribution Node.js predates PM2 7's Node >=18 contract.
// Use a private reviewed runtime there; never replace /usr/bin/node.
func pm2NodeBinaryOn(platform string) string {
	if platform == "ubuntu-22.04" {
		return "/opt/panel/app-modules/pm2/node/bin/node"
	}
	return "/usr/bin/node"
}
