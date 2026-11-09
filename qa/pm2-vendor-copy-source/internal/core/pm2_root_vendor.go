package core

import "local/panel/internal/appcatalog"

const PM2RootVendorAppVersion = appcatalog.PM2RootVendorVersion

// Fixed internal SQL only. Malformed/oversized and older control requests
// keep their existing worker; this exact revision can build dependencies.
const pm2RootVendorInstallQueuePredicate = "(kind='software_update' AND target_id='pm2-manager' AND CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 4096 THEN CASE WHEN json_valid(payload) THEN json_extract(payload,'$.version') ELSE '' END ELSE '' END='7.0.4-compat11')"
