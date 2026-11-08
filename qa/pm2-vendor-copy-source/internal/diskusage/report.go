package diskusage

// Wire models are portable; enumeration and kernel FD operations remain Linux-only.
type ScanBudget struct {
	Entries uint64 `json:"metadata_entries_max,string"`
	Depth   int    `json:"directory_depth_max"`
}

func DefaultScanBudget() ScanBudget { return ScanBudget{Entries: 10000000, Depth: 512} }

type UsageRow struct {
	Path           string `json:"path"`
	LogicalBytes   uint64 `json:"logical_bytes,string"`
	AllocatedBytes uint64 `json:"allocated_bytes,string"`
	Actionable     bool   `json:"path_actionable"`
	Links          uint32 `json:"link_count"`
}

// Complete is single-subtree enumeration, never an atomic or exclusive-space claim.
type ScanReport struct {
	Format                  int        `json:"format"`
	MountID                 string     `json:"mount_id"`
	BindingSHA              string     `json:"mount_binding_sha256"`
	SelectedPath            string     `json:"selected_path"`
	State                   string     `json:"state"`
	StartedAt               string     `json:"started_at"`
	FinishedAt              string     `json:"finished_at"`
	Complete                bool       `json:"enumeration_complete"`
	SnapshotConsistent      bool       `json:"snapshot_consistent"`
	ExclusivePhysicalBytes  bool       `json:"exclusive_physical_bytes"`
	IndexFlushed            bool       `json:"index_flushed"`
	Accounting              string     `json:"accounting"`
	DirectoryAttribution    string     `json:"directory_attribution"`
	Budget                  ScanBudget `json:"budget"`
	EntriesRead             uint64     `json:"metadata_entries_read,string"`
	Files                   uint64     `json:"regular_file_entries,string"`
	UniqueFiles             uint64     `json:"unique_regular_files,string"`
	Hardlinks               uint64     `json:"duplicate_regular_inodes,string"`
	Directories             uint64     `json:"directory_entries,string"`
	Links                   uint64     `json:"symbolic_links,string"`
	Special                 uint64     `json:"special_nodes,string"`
	LogicalBytes            uint64     `json:"regular_logical_entry_bytes,string"`
	UniqueLogicalBytes      uint64     `json:"regular_unique_logical_bytes,string"`
	FileAllocatedBytes      uint64     `json:"regular_allocated_bytes,string"`
	DirectoryAllocatedBytes uint64     `json:"directory_allocated_bytes,string"`
	LinkAllocatedBytes      uint64     `json:"symlink_allocated_bytes,string"`
	SpecialAllocatedBytes   uint64     `json:"special_allocated_bytes,string"`
	AllocatedBytes          uint64     `json:"inode_allocated_bytes,string"`
	Sparse                  uint64     `json:"allocation_below_logical_files,string"`
	MountBoundaries         uint64     `json:"excluded_child_mounts,string"`
	OwnWorkerDirectories    uint64     `json:"excluded_own_worker_directories,string"`
	UnknownEntries          uint64     `json:"unavailable_metadata_entries,string"`
	SkippedDirectories      uint64     `json:"skipped_directories,string"`
	Cycles                  uint64     `json:"duplicate_directory_inodes,string"`
	Reasons                 []string   `json:"partial_reasons"`
	TopFiles                []UsageRow `json:"top_files"`
	TopDirectories          []UsageRow `json:"top_directories"`
}

// Decimal strings preserve browser precision. Unknown values are null, not zero.
// Bind mounts, pools and subvolumes can overlap; these views must not be summed.
type Capacity struct {
	State              string  `json:"state"`
	TotalBytes         *string `json:"total_bytes"`
	FreeBytes          *string `json:"free_bytes"`
	AvailableBytes     *string `json:"available_bytes"`
	UsedBytes          *string `json:"used_bytes"`
	ReservedFreeBytes  *string `json:"reserved_free_bytes"`
	TotalInodes        *string `json:"total_inodes"`
	FreeInodes         *string `json:"free_inodes"`
	UsedInodes         *string `json:"used_inodes"`
	InodeState         string  `json:"inode_state"`
	ViewSHA            string  `json:"capacity_view_sha256"`
	MayOverlap         bool    `json:"capacity_may_overlap"`
	SnapshotConsistent bool    `json:"snapshot_consistent"`
}
