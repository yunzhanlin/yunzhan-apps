package core

import (
	"errors"
	"strings"
)

// LoadBalanceBackendTLS is explicit per-entry trust for business forwarding.
// It contains public certificates, never a client key, path, or insecure flag.
// The fixed node addresses remain the only network destinations.
type LoadBalanceBackendTLS struct {
	ServerName string `json:"server_name"`
	CAPEM      string `json:"ca_pem"`
}

func ValidateLoadBalanceBackendTLS(v *LoadBalanceBackendTLS) error {
	if v == nil {
		return nil
	}
	if !ValidDomain(v.ServerName) || strings.ToLower(v.ServerName) != v.ServerName {
		return errors.New("TLS 后端名称须为规范小写域名，用于 SNI、Host 与证书名称验证")
	}
	if v.CAPEM == "" {
		return errors.New("TLS 后端须提供入口专用公共 CA PEM；不自动安装全局信任或跳过验证")
	}
	_, err := LoadBalanceHealthRoots(v.CAPEM)
	return err
}
