package core

import "net/http"

type SiteLoadBalanceChoice struct {
	Domain string `json:"domain"`
	TLS    bool   `json:"tls"`
	Sticky bool   `json:"sticky"`
}

type SiteLoadBalanceChoices struct {
	Installed bool                    `json:"installed"`
	Entries   []SiteLoadBalanceChoice `json:"entries"`
}

func (a *Server) canBindSiteLoadBalance(u identity) bool {
	access, err := a.Store.UserAccess(u.ID)
	return err == nil && access.Role == "admin" && menuSubset([]string{"sites", ModuleMenu("load-balance")}, access.MenuIDs)
}

func (a *Server) checkSiteLoadBalanceChange(w http.ResponseWriter, u identity, site Site, next SiteSettings) bool {
	if site.Settings.LoadBalanceDomain == next.LoadBalanceDomain || a.canBindSiteLoadBalance(u) {
		return true
	}
	fail(w, http.StatusForbidden, "绑定或解除入口需要网站和系统工具管理权限")
	return false
}
