package core

type SiteBackup struct {
	ID          string `json:"id"`
	SiteID      string `json:"site_id"`
	Format      string `json:"format"`
	Files       int    `json:"files"`
	SourceBytes int64  `json:"source_bytes"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	CreatedAt   string `json:"created_at"`
}

type SiteRestoreRequest struct {
	JobID  string     `json:"job_id"`
	Site   Site       `json:"site"`
	Backup SiteBackup `json:"backup"`
}
