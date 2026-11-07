package core

import (
	"context"
	"strconv"

	"local/panel/internal/diskjob"
)

func (s *Store) HostDiskInventoryRequest(ctx context.Context, actor string) (diskjob.InventoryRequest, error) {
	access, err := hostDiskAuthority(ctx, s.DB, actor)
	if err != nil {
		return diskjob.InventoryRequest{}, err
	}
	return diskjob.InventoryRequest{Format: 1, ActorID: actor, AccessRevision: strconv.FormatInt(access.Revision, 10)}, nil
}

func (s *Store) ValidateHostDiskInventory(ctx context.Context, in diskjob.InventoryRequest) error {
	current, err := s.HostDiskInventoryRequest(ctx, in.ActorID)
	if err != nil || current != in {
		return errHostDiskAuthority
	}
	return nil
}
