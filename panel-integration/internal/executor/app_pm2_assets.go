package executor

import _ "embed"

//go:embed pm2-assets/package.json
var pm2Package []byte

//go:embed pm2-assets/package-lock.json
var pm2Lock []byte
