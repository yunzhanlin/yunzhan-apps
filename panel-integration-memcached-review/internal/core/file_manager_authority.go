package core

import "context"

// Shared SMTP and backup profiles are global administrator credentials, not
// capabilities conferred by a site's ordinary file-write permission. Re-read
// current authority before retrieving any stored profile or plaintext secret.
func (a *Server) fileSharedInfrastructureAllowed(ctx context.Context, actor identity) bool {
	access, err := readUserAccessContext(ctx, a.Store.DB, actor.ID)
	return err == nil && ctx.Err() == nil && fullAdministrator(access)
}
