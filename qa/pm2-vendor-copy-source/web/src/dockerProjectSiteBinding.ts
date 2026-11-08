export interface DockerProjectSiteState {
  template_id?: string;
  state?: string;
  services?: number;
  running?: number;
  healthy?: number;
  host_port?: number;
  site_name?: string;
}
// Presentation only. The authenticated backend independently re-reads the
// current executor state; this function cannot authorize a binding.
export function canBindDockerProjectSite(project: DockerProjectSiteState): boolean {
  const template = project.template_id;
  const known = template === "nginx-static" || template === "wordpress-blog" ||
    template === "openlitespeed" || /^php-legacy-(52|53|54|55|56|70|71|72|73|74|80|81)$/.test(template || "");
  return known && !project.site_name && project.state === "running" &&
    Number.isSafeInteger(project.services) && project.services! > 0 &&
    project.running === project.services && project.healthy === project.services &&
    Number.isSafeInteger(project.host_port) && project.host_port! >= 1024 && project.host_port! <= 65535;
}
