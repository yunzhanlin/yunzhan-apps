package core

import (
	"errors"
	"net/netip"
)

// Trust applies only to the explicitly listed network peers on WAF-managed
// servers. It never discovers proxy ranges or trusts arbitrary headers.
type WAFTrustedProxyConfig struct {
	Enabled                  bool     `json:"enabled"`
	Header                   string   `json:"header"`
	Recursive                bool     `json:"recursive"`
	TrustedCIDRs             []string `json:"trusted_cidrs"`
	AcknowledgeHeaderControl bool     `json:"acknowledge_header_control"`
}

func ValidateWAFTrustedProxy(v *WAFTrustedProxyConfig) error {
	if v == nil {
		return nil
	}
	if (v.Header != "X-Forwarded-For" && v.Header != "X-Real-IP") || len(v.TrustedCIDRs) > 32 || v.TrustedCIDRs == nil {
		return errors.New("可信反代仅接受 X-Forwarded-For 或 X-Real-IP 和最多 32 个明确 CIDR 网段")
	}
	if v.Enabled && (!v.AcknowledgeHeaderControl || len(v.TrustedCIDRs) == 0) {
		return errors.New("启用前须列出可信代理 CIDR 并确认这些代理会正确清洗和设置访客地址头")
	}
	if v.Header == "X-Real-IP" && v.Recursive {
		return errors.New("X-Real-IP 为单个访客地址，不启用多级代理链递归")
	}
	var prefixes []netip.Prefix
	for _, text := range v.TrustedCIDRs {
		p, err := netip.ParsePrefix(text)
		if err != nil || p.String() != text || p != p.Masked() || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().String() == "255.255.255.255" || (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
			return errors.New("可信代理须为规范 IPv4/IPv6 CIDR；拒绝 DNS、Unix、端口、映射地址、组播、全网和过宽网段（IPv4 至少 /8，IPv6 至少 /32）")
		}
		for _, previous := range prefixes {
			if p.Contains(previous.Addr()) || previous.Contains(p.Addr()) {
				return errors.New("可信代理网段重复或重叠，请明确最小信任范围")
			}
		}
		prefixes = append(prefixes, p)
	}
	return nil
}
