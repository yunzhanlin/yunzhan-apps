//go:build !linux && !darwin

package appcatalog

import "errors"

type manifestCache struct{}

func openManifestCache(string, CatalogItem) (*manifestCache, error) {
	return nil, errors.New("当前平台不支持受限应用包缓存")
}
func (*manifestCache) Close() error { return nil }
func (*manifestCache) Read() ([]byte, error) {
	return nil, errors.New("当前平台不支持受限应用包缓存")
}
func (*manifestCache) Publish([]byte) error {
	return errors.New("当前平台不支持受限应用包缓存")
}
