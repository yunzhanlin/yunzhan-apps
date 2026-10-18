//go:build !linux

package executor

func (s *Service) lockApacheWAFSiteMutation() (func(), error) { return func() {}, nil }
