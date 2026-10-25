package core

// Official multi-architecture stable image, verified against the OCI registry
// index and docker-library/repo-info on 2026-10-19. Only NEW projects use this
// template: existing projects keep their original compose bytes and volumes.
// https://github.com/docker-library/repo-info/blob/master/repos/nginx/remote/1.30.6-alpine.md
const dockerNginxStaticImage = "nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5"

func dockerProjectSiteBindingAllowed(template, state string, services, running, healthy, port int) bool {
	_, legacy := LegacyPHPImages[template]
	bindable := template == "nginx-static" || template == "wordpress-blog" || template == "openlitespeed" || legacy
	return bindable && state == "running" && services > 0 && running == services && healthy == services && port >= 1024 && port <= 65535
}
