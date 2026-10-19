//go:build !linux

package executor

func (s *Service) StartNetworkIDSOperations() error { return nil }
