package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
)

const AnalyticsProxyTokenHeader = "X-Yunzhan-Analytics-Proxy"
const AnalyticsProxyClientHeader = "X-Yunzhan-Analytics-Client-IP"
const AnalyticsClientAddressAppVersion = "2.3.2"

// This domain-separated key is for the collector only. The original account
// key is never written to Nginx, returned in a preview, or sent by the tracker.
func AnalyticsProxyToken(key []byte, siteID string) (string, error) {
	if len(key) != 32 || !ValidID(siteID) {
		return "", errors.New("采集代理身份的主密钥或网站标识无效")
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("yunzhan-analytics-ingress-v1\x00" + siteID))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func AnalyticsProxyIdentity(key []byte, siteID string) (string, error) {
	token, err := AnalyticsProxyToken(key, siteID)
	if err != nil {
		return "", err
	}
	return Hash("yunzhan-analytics-include-v1\x00" + token), nil
}

func analyticsPeerAddress(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, errors.New("采集连接地址无效")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, errors.New("采集连接地址无效")
	}
	return ip.Unmap(), nil
}

// Ordinary forwarding headers never grant collector identity. Only the
// root-private managed include may supply this independent per-site token.
func (a *Server) analyticsClientAddress(r *http.Request, site Site, peer netip.Addr) (string, string, error) {
	tokens, clients := r.Header.Values(AnalyticsProxyTokenHeader), r.Header.Values(AnalyticsProxyClientHeader)
	if len(tokens) == 0 && len(clients) == 0 {
		if peer.IsLoopback() {
			return "", "unknown_proxy", nil
		}
		return peer.String(), "direct", nil
	}
	if !peer.IsLoopback() || len(tokens) != 1 || len(clients) != 1 || site.Settings.AnalyticsEndpoint == "" || site.Settings.AnalyticsProxyIdentity == "" {
		return "", "", errors.New("采集代理身份或地址未通过核对")
	}
	token, err := AnalyticsProxyToken(a.accountSecretKey, site.ID)
	identity, idErr := AnalyticsProxyIdentity(a.accountSecretKey, site.ID)
	if err != nil || idErr != nil || !hmac.Equal([]byte(site.Settings.AnalyticsProxyIdentity), []byte(identity)) || !hmac.Equal([]byte(tokens[0]), []byte(token)) {
		return "", "", errors.New("采集代理身份或地址未通过核对")
	}
	client, err := netip.ParseAddr(clients[0])
	if err != nil || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
		return "", "", errors.New("采集代理身份或地址未通过核对")
	}
	return client.Unmap().String(), "managed_proxy", nil
}
