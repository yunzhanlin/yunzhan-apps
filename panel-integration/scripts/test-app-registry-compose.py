#!/usr/bin/env python3
"""Verify signed registry installs and real MongoDB/Elasticsearch lifecycles."""

import json
import os
import pathlib
import time
import uuid

from panel_client import PanelClient


ROOT = pathlib.Path(__file__).resolve().parents[1]


def wait_docker(client, job, timeout=1200):
    deadline = time.monotonic() + timeout
    current = job
    while current.get("state") in ("queued", "running") and time.monotonic() < deadline:
        time.sleep(2)
        current = client.api("/docker/jobs/" + job["job_id"])
    if current.get("state") != "succeeded":
        raise RuntimeError("Docker job failed: " + current.get("error", "unknown error"))
    return current


def project_for(client, template_id):
    projects = client.api("/docker/projects").get("projects", [])
    rows = [item for item in projects if item.get("template_id") == template_id]
    if len(rows) != 1:
        raise RuntimeError(f"expected one {template_id} project, found {len(rows)}")
    return rows[0]


def wait_registry_health(client, app_id, timeout=420):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        page = client.api("/app-registry")
        status = next(item for item in page["status"] if item["id"] == app_id)
        if status["installed"] and status["healthy"]:
            return status
        time.sleep(4)
    raise RuntimeError(f"{app_id} health probe did not become healthy")


def shell(client, command):
    result = client.vm("bash", "-lc", command)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "guest command failed")
    return result.stdout.strip()


def wait_elastic_document(client):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        response = client.vm('curl', '-fsS', '--max-time', '5', 'http://127.0.0.1:19200/yunzhan_acceptance/_doc/1', check=False)
        if response.returncode == 0:
            value = json.loads(response.stdout)
            if value.get('_source', {}).get('marker') == 'registry-ok':
                return
        time.sleep(2)
    raise RuntimeError('Elasticsearch document lost or unavailable after restart')


def container_id(client, project):
    engine = project["engine_name"]
    return shell(client, "sudo docker ps --filter label=com.docker.compose.project=" + engine + " --format '{{.ID}}' | head -1")


def main():
    client = PanelClient()
    created = []
    before_volumes = {item["Name"] for item in client.api("/docker/volumes").get("volumes", [])}
    report = {"checks": [], "apps": {}}
    try:
        registry = client.api("/app-registry")
        if len(registry["catalog"]["apps"]) != 50 or registry["source"]["source"] not in ("github", "verified-cache"):
            raise RuntimeError("signed registry catalog is incomplete")
        ready = {item["id"] for item in registry["catalog"]["apps"] if item["stage"] == "ready"}
        if not {"mongodb", "elasticsearch"}.issubset(ready):
            raise RuntimeError("new applications are not published as ready")
        report["checks"].append("loaded the 50-item Ed25519-verified GitHub catalog")

        mongo_job = client.api(
            "/app-registry/mongodb/install",
            {"name": "accept-mongodb", "host_port": 27018},
            idempotency_key="registry-mongodb-" + uuid.uuid4().hex,
        )
        wait_docker(client, mongo_job)
        mongo = project_for(client, "mongodb")
        created.append(mongo)
        wait_registry_health(client, "mongodb")
        mongo_id = container_id(client, mongo)
        marker = shell(
            client,
            "sudo docker exec " + mongo_id + " sh -lc 'mongosh --quiet --username \"$MONGO_INITDB_ROOT_USERNAME\" --password \"$MONGO_INITDB_ROOT_PASSWORD\" --authenticationDatabase admin --eval '\"'\"'db=db.getSiblingDB(\"yunzhan_acceptance\"); db.checks.deleteMany({}); db.checks.insertOne({marker:\"registry-ok\"}); print(db.checks.findOne({}).marker)'\"'\"''",
        )
        if marker.splitlines()[-1] != "registry-ok":
            raise RuntimeError("MongoDB marker round trip failed")
        report["apps"]["mongodb"] = {"project_id": mongo["id"], "port": mongo["host_port"], "marker": "registry-ok"}
        report["checks"].append("installed digest-pinned MongoDB, passed container health and authenticated write/read")

        elastic_job = client.api(
            "/app-registry/elasticsearch/install",
            {"name": "accept-elasticsearch", "host_port": 19200},
            idempotency_key="registry-elasticsearch-" + uuid.uuid4().hex,
        )
        wait_docker(client, elastic_job)
        elastic = project_for(client, "elasticsearch")
        created.append(elastic)
        if os.environ.get('APP_ES_QA_SINGLE_CPU') == '1':
            # QEMU cross-ISA SMP can crash HotSpot C1. Constrain only this owned
            # QA container; never change the published image or JVM settings.
            elastic_id = container_id(client, elastic)
            assert elastic_id and all(ch in '0123456789abcdef' for ch in elastic_id)
            client.vm('sudo', 'docker', 'update', '--cpuset-cpus', '0', elastic_id)
            wait_docker(client, client.api(f"/docker/projects/{elastic['id']}/stop", {}, idempotency_key=uuid.uuid4().hex))
            wait_docker(client, client.api(f"/docker/projects/{elastic['id']}/start", {}, idempotency_key=uuid.uuid4().hex))
            assert shell(client, 'sudo docker inspect --format "{{.HostConfig.CpusetCpus}}" ' + container_id(client, elastic)) == '0'
            report['elasticsearch_qa_cpu_affinity'] = '0'
        wait_registry_health(client, "elasticsearch", timeout=1200)
        if report.get('elasticsearch_qa_cpu_affinity'):
            assert int(shell(client, 'sudo docker inspect --format "{{.RestartCount}}" ' + container_id(client, elastic))) == 0, 'JVM crashed before initial health under single-CPU QA affinity'
        shell(client, "curl -fsS -X PUT -H 'Content-Type: application/json' --data '{\"marker\":\"registry-ok\"}' http://127.0.0.1:19200/yunzhan_acceptance/_doc/1 >/dev/null")
        search = shell(client, "curl -fsS http://127.0.0.1:19200/yunzhan_acceptance/_doc/1")
        if json.loads(search).get("_source", {}).get("marker") != "registry-ok":
            raise RuntimeError("Elasticsearch marker round trip failed")
        report["apps"]["elasticsearch"] = {"project_id": elastic["id"], "port": elastic["host_port"], "marker": "registry-ok"}
        report["checks"].append("installed digest-pinned Elasticsearch, passed cluster health and indexed/read a document")

        for project in created:
            wait_docker(client, client.api(f"/docker/projects/{project['id']}/stop", {}, idempotency_key=uuid.uuid4().hex))
            wait_docker(client, client.api(f"/docker/projects/{project['id']}/start", {}, idempotency_key=uuid.uuid4().hex))
        wait_registry_health(client, "mongodb")
        wait_registry_health(client, "elasticsearch", timeout=1200)
        mongo_marker = shell(client, "sudo docker exec " + container_id(client, mongo) + " sh -lc 'mongosh --quiet --username \"$MONGO_INITDB_ROOT_USERNAME\" --password \"$MONGO_INITDB_ROOT_PASSWORD\" --authenticationDatabase admin --eval '\"'\"'print(db.getSiblingDB(\"yunzhan_acceptance\").checks.findOne({}).marker)'\"'\"''")
        assert mongo_marker.splitlines()[-1] == "registry-ok", "MongoDB document lost after restart"
        wait_elastic_document(client)
        for _ in range(6):
            time.sleep(5)
            wait_elastic_document(client)
        report['mongodb_document_after_restart'] = True
        report['elasticsearch_document_after_restart'] = True
        report['elasticsearch_final_restart_count'] = int(shell(client, 'sudo docker inspect --format "{{.RestartCount}}" ' + container_id(client, elastic)))
        if report.get('elasticsearch_qa_cpu_affinity'):
            assert report['elasticsearch_final_restart_count'] == 0, 'JVM still crashed under single-CPU QA affinity'
        report["checks"].append("stopped and restarted both Compose projects, recovered healthy state and retained both actual documents")
    finally:
        for project in reversed(created):
            try:
                wait_docker(client, client.api(f"/docker/projects/{project['id']}", {"confirm_name": project["name"]}, method="DELETE"))
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(str(error))
        try:
            after = client.api("/docker/volumes").get("volumes", [])
            for volume in after:
                name = volume["Name"]
                if name not in before_volumes and any(name.startswith(p['engine_name']+'_') for p in created):
                    client.api("/docker/volumes/" + name, {"confirm_name": name}, method="DELETE")
        except Exception as error:
            report.setdefault("cleanup_errors", []).append(str(error))
        client.close()
    report["cleanup_ok"] = not report.get("cleanup_errors")
    output = ROOT / ".local/app-registry-compose-acceptance.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if not report["cleanup_ok"]:
        raise RuntimeError("acceptance cleanup failed")
    print("PASS signed catalog, MongoDB and Elasticsearch real lifecycle with cleanup")


if __name__ == "__main__":
    main()
