#!/usr/bin/env python3
"""Verify the signed phpMyAdmin package and its real Compose lifecycle."""

import json
import pathlib
import time
import uuid
import os

from panel_client import PanelClient


ROOT = pathlib.Path(__file__).resolve().parents[1]
assert os.environ.get('PANEL_VM') in ('panel-store-apps-debian13', 'panel-compat-ubuntu24'), 'Explicit isolated application QA VM required'


def wait_job(client, job, timeout=600):
    deadline = time.monotonic() + timeout
    current = job
    while current.get("state") in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(2)
        current = client.api("/docker/jobs/" + job["job_id"])
    if current.get("state") != "succeeded":
        raise RuntimeError("Docker job failed: " + current.get("error", "unknown error"))


def wait_healthy(client, timeout=420):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        page = client.api("/app-registry")
        status = next(item for item in page["status"] if item["id"] == "phpmyadmin")
        if status["installed"] and status["healthy"]:
            return
        time.sleep(4)
    raise RuntimeError("phpMyAdmin did not become healthy")


def main():
    client = PanelClient()
    project = None
    before_volumes = {item["Name"] for item in client.api("/docker/volumes").get("volumes", [])}
    report = {"checks": []}
    try:
        registry = client.api("/app-registry")
        app = next(item for item in registry["catalog"]["apps"] if item["id"] == "phpmyadmin")
        if len(registry["catalog"]["apps"]) != 50 or app["stage"] != "ready":
            raise RuntimeError("signed phpMyAdmin package is not ready")
        report["checks"].append("loaded phpMyAdmin from the 50-item Ed25519-verified GitHub catalog")

        wait_job(client, client.api(
            "/app-registry/phpmyadmin/install",
            {"name": "accept-phpmyadmin", "host_port": 18080},
            idempotency_key="registry-phpmyadmin-" + uuid.uuid4().hex,
        ))
        projects = [item for item in client.api("/docker/projects").get("projects", []) if item.get("template_id") == "phpmyadmin"]
        if len(projects) != 1:
            raise RuntimeError("expected exactly one phpMyAdmin project")
        project = projects[0]
        wait_healthy(client)
        response = client.vm("bash", "-lc", "curl -fsS http://127.0.0.1:18080/ | grep -q phpMyAdmin")
        if response.returncode:
            raise RuntimeError("phpMyAdmin private HTTP page failed")
        report["checks"].append("installed the digest-pinned image and verified the private HTTP login page")
        if os.environ.get('APP_PMA_SQL_QA') == '1':
            from test_pma_sql_common import verify_sql
            report['checks'].append(verify_sql(client, project))
            report['authenticated_sql'] = True

        wait_job(client, client.api(f"/docker/projects/{project['id']}/stop", {}, idempotency_key=uuid.uuid4().hex))
        wait_job(client, client.api(f"/docker/projects/{project['id']}/start", {}, idempotency_key=uuid.uuid4().hex))
        wait_healthy(client)
        report["checks"].append("stopped, restarted and recovered the healthy project")
    finally:
        if project:
            try:
                wait_job(client, client.api(f"/docker/projects/{project['id']}", {"confirm_name": project["name"]}, method="DELETE"))
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(str(error))
        try:
            for volume in client.api("/docker/volumes").get("volumes", []):
                name = volume["Name"]
                if project and name not in before_volumes and name.startswith(project['engine_name']+'_'):
                    client.api("/docker/volumes/" + name, {"confirm_name": name}, method="DELETE")
        except Exception as error:
            report.setdefault("cleanup_errors", []).append(str(error))
        client.close()
    report["cleanup_ok"] = not report.get("cleanup_errors")
    (ROOT / ".local/app-registry-phpmyadmin-acceptance.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if not report["cleanup_ok"]:
        raise RuntimeError("phpMyAdmin acceptance cleanup failed")
    print("PASS signed phpMyAdmin install, HTTP health, restart and cleanup")


if __name__ == "__main__":
    main()
