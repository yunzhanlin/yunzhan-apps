//go:build !linux

package executor

func (s *Service) lockWAFSiteMutation() (func(), error) { return func() {}, nil }

func (s *Service) preserveWAFBodySiteConfig(content, _ string) (string, error) {
	return content, nil
}
