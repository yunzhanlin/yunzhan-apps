package executor

import (
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Equality of two decoded records is ONLY a binding prerequisite. A caller can
// fabricate both records: this function never supplies a signature, a live Core
// administrator revision, an original Root lease or permission for an effect.
func loadBalanceStreamInstallationGrantMatches(seedRaw []byte, grant core.LoadBalanceStreamInstallAuthority) bool {
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	return err == nil && grant.Format == 1 &&
		grant.JobID == seed.JobID && grant.ActorID == seed.ActorID &&
		grant.Action == seed.Action && grant.AppVersion == seed.AppVersion &&
		grant.ManifestSHA256 == seed.ManifestSHA256 && grant.PayloadSHA256 == seed.PayloadSHA256 &&
		grant.OriginalRequestSHA256 == seed.OriginalRequestSHA256 && grant.KeySHA256 == seed.KeySHA256 &&
		grant.AccessRevision == seed.AccessRevision && grant.ActorObservationSHA256 == seed.ActorObservationSHA256 &&
		grant.JobCreatedAt == seed.JobCreatedAt
}
