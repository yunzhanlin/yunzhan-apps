package core

type LogCleanupRequest struct {
	SiteID        string `json:"site_id"`
	RetentionDays int    `json:"retention_days"`
}

type LogCleanupResult struct {
	Rotated      int      `json:"rotated"`
	Deleted      int      `json:"deleted"`
	DeletedBytes int64    `json:"deleted_bytes"`
	Files        []string `json:"files"`
}
