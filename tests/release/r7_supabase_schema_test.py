#!/usr/bin/env python3
"""Exercise the shipped Supabase bootstrap and PostgreSQL RPCs offline."""

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "supabase" / "nli_schema.sql"
SECRET_PLACEHOLDER = "__NLI_CONTROLLER_SECRET_SHA256__"

SUPABASE_FIXTURE = """
create role anon nologin;
create role authenticated nologin;
create schema storage;
create table storage.buckets (
    id text primary key,
    name text not null,
    public boolean not null,
    file_size_limit bigint,
    allowed_mime_types text[]
);
"""


def docker(*arguments, sql=None, check=True):
    result = subprocess.run(
        ["docker", *arguments], input=sql, text=True, encoding="utf-8",
        capture_output=True, timeout=40, check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"docker {arguments[0]} failed: {result.stderr.strip()}")
    return result


def execute(container, sql, check=True):
    return docker(
        "exec", "-i", container, "psql", "-X", "-qAt", "-U", "postgres",
        "-d", "postgres", "--set=ON_ERROR_STOP=1", "--set=VERBOSITY=verbose",
        sql=sql, check=check,
    )


def wait_for_database(container):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        logs = docker("logs", container)
        if "PostgreSQL init process complete" in logs.stdout:
            if docker("exec", container, "pg_isready", "-q", "-U", "postgres", check=False).returncode == 0:
                return
        time.sleep(0.25)
    raise RuntimeError("isolated PostgreSQL did not start within 30 seconds")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_fixture(value):
    """Canonicalize the small ASCII fixture, whose numbers are exactly representable."""
    if isinstance(value, dict):
        value = {key: canonical_fixture(item) for key, item in value.items()}
    elif isinstance(value, list):
        value = [canonical_fixture(item) for item in value]
    elif isinstance(value, float) and value.is_integer():
        value = int(value)
    return value


def canonical_bytes(value):
    return json.dumps(canonical_fixture(value), sort_keys=True, separators=(",", ":")).encode("ascii")


def sql_string(value):
    return "'" + value.replace("'", "''") + "'"


def rpc(container, secret, expression, *, role="anon", expect_denied=False):
    headers = {} if secret is None else {"x-nli-controller-secret": secret}
    result = execute(
        container,
        f"set role {role};\nset request.headers = {sql_string(json.dumps(headers))};\n"
        f"select {expression};\n",
        check=not expect_denied,
    )
    if expect_denied:
        assert result.returncode != 0 and "42501" in result.stderr, result.stderr
        return None
    return json.loads(result.stdout)


def put(container, secret, collection, identity, state, raw_payload):
    digest = sha256(canonical_bytes(json.loads(raw_payload)))
    parameters = [collection, identity, state, raw_payload, digest, "isolated-test"]
    return rpc(container, secret, "public.nli_put_document(" + ",".join(map(sql_string, parameters)) + ")")


def verify_schema(container, source):
    if source.count(SECRET_PLACEHOLDER) != 1:
        raise RuntimeError("shipped bootstrap must contain one controller digest placeholder")
    secret = secrets.token_hex(32)
    wrong_secret = secrets.token_hex(32)
    bootstrap = source.replace(SECRET_PLACEHOLDER, sha256(secret.encode("ascii")))

    execute(container, SUPABASE_FIXTURE)
    execute(container, bootstrap)
    health = rpc(container, secret, "public.nli_health()")
    assert health["status"] == "ok" and health["schema_version"] == 1 and health["revisions"] == 0
    buckets = json.loads(execute(container, "select json_agg(id order by id) from storage.buckets where not public;").stdout)
    assert buckets == ["nli-assurance-fixtures", "nli-geoip-databases", "nli-rollout-artifacts"]
    rpc(container, None, "public.nli_health()", expect_denied=True)
    rpc(container, secret, "public.nli_health()", role="authenticated", expect_denied=True)
    rpc(container, secret, "(select count(*) from public.nli_documents)", expect_denied=True)

    prior = put(container, secret, "parser-packs", "synthetic-existing-pack", "draft", '{"name":"initial"}')
    latest = put(container, secret, "parser-packs", "synthetic-existing-pack", "published", '{"name":"reviewed"}')
    assert prior["revision"] == 1 and latest["revision"] == 2

    # JSONB may reorder object properties and retain different numeric spellings.
    # The RPC must round-trip the canonical bytes used by the controller's export.
    raw_content = '{"schema_version":1,"bundle":{"assets":[{"z":1.000,"a":1.25e-1}],"schema_version":1},"scope":{"settings":["kv-config"]}}'
    snapshot_bytes = canonical_bytes(json.loads(raw_content))
    snapshot_id = sha256(snapshot_bytes)
    content = put(container, secret, "bundle-backup-content", snapshot_id, "verified", raw_content)
    assert content["sha256"] == snapshot_id
    manifest = put(container, secret, "bundle-backups", snapshot_id, "verified", json.dumps({"snapshot_hash": snapshot_id}))
    assert manifest["revision"] == 1
    plan = put(container, secret, "bundle-restore-plans", snapshot_id, "verified", '{"operations":[]}')
    proposal = put(container, secret, "bundle-restores", "restore-fixture", "pending_approval", '{"base_revision":"base-fixture"}')
    journal = put(container, secret, "bundle-restore-journal", "current", "applying", '{"restore_id":"restore-fixture"}')
    committed = put(container, secret, "bundle-restore-journal", "current", "controller_published", '{"restore_id":"restore-fixture"}')
    assert [plan["revision"], proposal["revision"], journal["revision"], committed["revision"]] == [1, 1, 1, 2]

    listed = rpc(container, secret, "public.nli_list_documents('bundle-backups','verified',1,0)")
    assert listed == [manifest]
    assert rpc(container, secret, "public.nli_list_documents('bundle-backups','verified',1,1)") == []
    exported = rpc(container, secret, f"public.nli_get_document('bundle-backup-content','{snapshot_id}',0)")
    assert canonical_bytes(exported["payload"]) == snapshot_bytes
    assert sha256(canonical_bytes(exported["payload"])) == exported["sha256"] == snapshot_id

    before = rpc(container, secret, "public.nli_health()")
    execute(container, bootstrap)
    assert rpc(container, secret, "public.nli_health()") == before
    assert rpc(container, secret, "public.nli_get_document('parser-packs','synthetic-existing-pack',1)") == prior
    assert rpc(container, secret, "public.nli_get_document('parser-packs','synthetic-existing-pack',0)") == latest
    assert rpc(container, secret, "public.nli_get_document('bundle-restore-journal','current',1)") == journal
    assert rpc(container, secret, "public.nli_get_document('bundle-restore-journal','current',0)") == committed

    rpc(container, wrong_secret, "public.nli_health()", expect_denied=True)
    rpc(container, wrong_secret, "public.nli_delete_document('parser-packs','synthetic-existing-pack',true,'isolated-test')", expect_denied=True)
    rpc(container, wrong_secret, "public.nli_list_documents('bundle-backups')", expect_denied=True)
    assert rpc(container, secret, "public.nli_health()") == before
    assert rpc(container, secret, "public.nli_get_document('parser-packs','synthetic-existing-pack',0)") == latest

    # The shipped SQL is an administrator-only, rendered bootstrap. Applying
    # it with a different digest rotates the credential, without deleting data.
    execute(container, source.replace(SECRET_PLACEHOLDER, sha256(wrong_secret.encode("ascii"))))
    rpc(container, secret, "public.nli_health()", expect_denied=True)
    assert rpc(container, wrong_secret, "public.nli_health()") == before
    assert rpc(container, wrong_secret, f"public.nli_get_document('bundle-backup-content','{snapshot_id}',0)") == exported

    return {
        "bootstrap_release": health["bootstrap_release"],
        "rpc_schema_version": health["schema_version"],
        "first_bootstrap_and_private_bucket_definitions": "passed",
        "matching_bootstrap_preserves_immutable_revisions": "passed",
        "mismatched_rpc_secret_refuses_read_and_destructive_rpc": "passed",
        "privileged_bootstrap_with_other_secret": "rotates credential and preserves revisions",
        "generic_recovery_collections_and_paginated_browse": "passed",
        "jsonb_canonical_snapshot_bytes_and_sha256_roundtrip": "passed",
        "preserved_revisions": before["revisions"],
        "network": "none",
        "production_projects_modified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="postgres:17.6-alpine", help="existing local PostgreSQL image")
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    container = "nli-r7-schema-" + uuid.uuid4().hex[:12]
    schema = SCHEMA.read_bytes()

    docker(
        "run", "--rm", "-d", "--pull=never", "--name", container, "--network", "none",
        "--tmpfs", "/var/lib/postgresql/data", "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
        args.image, "-c", "listen_addresses=",
    )
    try:
        wait_for_database(container)
        evidence = verify_schema(container, schema.decode("utf-8"))
        evidence["schema_sha256"] = sha256(schema)
        evidence["postgres_version"] = execute(container, "show server_version;").stdout.strip()
    finally:
        docker("rm", "--force", container)

    result = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    args.result.write_bytes(result.encode("utf-8"))
    print(result, end="")


if __name__ == "__main__":
    main()
