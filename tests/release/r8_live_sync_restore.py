#!/usr/bin/env python3
"""Qualify exact parser rollout and restore on the packaged Docker fixtures."""

import argparse
from http.cookiejar import CookieJar
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
from urllib import error, request


API = "/api/v1"


class QualificationFailure(RuntimeError):
    pass


class APIError(QualificationFailure):
    def __init__(self, method, path, status):
        super().__init__(f"{method} {path} returned HTTP {status}")
        self.status = status


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Session:
    def __init__(self, endpoint, username, password):
        self.endpoint = endpoint
        self.csrf = None
        # main() confines this self-signed TLS exception to the loopback
        # listener of a Docker fixture with local metadata storage.
        self.opener = request.build_opener(
            request.ProxyHandler({}), NoRedirect(),
            request.HTTPCookieProcessor(CookieJar()),
            request.HTTPSHandler(context=ssl._create_unverified_context()),
        )
        self.call("POST", "/auth/login", {"username": username, "password": password})
        self.csrf = self.call("GET", "/auth/csrf")["csrf_token"]

    def call(self, method, path, payload=None, expected=200):
        headers = {"Accept": "application/json"}
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        req = request.Request(self.endpoint + API + path, body, headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as reply:
                if reply.status != expected:
                    raise APIError(method, path, reply.status)
                return json.load(reply)
        except error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise APIError(method, path, status) from None


def require(condition, message):
    if not condition:
        raise QualificationFailure(message)


def wait_for(description, timeout, probe):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except APIError as exc:
            if exc.status not in (429, 502, 503, 504):
                raise
        except (error.URLError, TimeoutError):
            pass
        time.sleep(2)
    raise QualificationFailure(f"Timed out waiting for {description}")


def wait_for_single_client(admin, timeout):
    def probe():
        clients = admin.call("GET", "/parser-sync/runtime")["clients"]
        require(len(clients) <= 1, "Expected only the freshly enrolled fixture client")
        return clients[0]["node_id"] if clients else None

    return wait_for("one enrolled client", timeout, probe)


def wait_for_exact_runtime(admin, state_dir, node, digest, timeout, live_id=None):
    def probe():
        runtime = admin.call("GET", "/parser-sync/runtime")
        bundle = runtime["bundle"]
        client = next((row for row in runtime["clients"] if row["node_id"] == node), {})
        require(client.get("status") != "failed", "Fixture client reported parser bundle application failed")
        if not (
            bundle["desired_hash"] == digest == bundle["controller_applied_hash"]
            and bundle["controller_status"] == "applied"
            and client.get("desired_hash") == digest == client.get("applied_hash")
            and client.get("status") == "applied"
            and client.get("exact_acknowledgement") is True
        ):
            return None
        if live_id:
            rollout = admin.call("GET", f"/rollouts/{live_id}")
            require(rollout["status"] not in ("failed", "cancelled"), "Live parser rollout failed")
            if rollout["status"] != "completed" or rollout["node_results"][node]["status"] != "completed":
                return None
        on_disk = json.loads((state_dir / "parser-assets" / "bundle.json").read_text(encoding="utf-8"))
        require(on_disk["bundle_hash"] == digest, "Controller bundle on disk differs from exact runtime acknowledgement")
        return on_disk

    return wait_for("controller application and exact client acknowledgement", timeout, probe)


def require_approval_gate(session, node, digest):
    verification = session.call("POST", "/parser-sync/verify", {"node_ids": [node], "bundle_hash": digest})
    require(verification["controller_applied_hash"] == digest, "Controller did not materialize the desired bundle")
    acknowledgements = verification["client_acknowledgements"]
    require(
        len(acknowledgements) == 1 and acknowledgements[0]["node_id"] == node
        and acknowledgements[0]["exact_acknowledgement"] is False,
        "New desired bundle reached exact client acknowledgement before independent rollout approval",
    )


def approve_rollout(reviewer, reviewer_name, proposal_id, digest, node):
    detail = reviewer.call("GET", f"/rollouts/{proposal_id}")
    require(detail["state"] == "pending_approval", "Parser rollout proposal bypassed approval")
    proposal = detail["payload"]
    require(proposal["bundle_hash"] == digest and proposal["target_nodes"] == [node], "Rollout proposal pinned a different bundle or target")
    approved = reviewer.call("POST", f"/rollouts/{proposal_id}/approve", {"reason": "Independently verified the synthetic fixture bundle"})
    payload = approved["payload"]
    require(approved["state"] == "active" and payload["approved_by"] == reviewer_name, "Independent fleet approval was not recorded")
    return payload["live_rollout_id"]


def bundle_content(bundle):
    return {
        (asset["asset_class"], asset["asset_id"]): (asset["name"], asset["sha256"], asset["payload"])
        for asset in bundle["assets"]
    }


def embedded_references(session):
    assets = session.call("GET", "/parser-sync/runtime")["assets"]
    return {
        (asset["asset_class"], asset["asset_id"]): asset["parser_pack_id"]
        for asset in assets if asset.get("runtime_disposition") == "embedded_reference"
    }


def qualify(endpoint, config, password, timeout):
    state_dir = Path(config["state_dir"])
    metadata_dir = Path(config.get("storage_dir") or state_dir / "metadata")
    admin = Session(endpoint, "admin", password)
    node = wait_for_single_client(admin, timeout)
    suffix = secrets.token_hex(4)
    reviewer_name = "r8-review-" + suffix
    reviewer_password = "Fixture-Review-!" + secrets.token_urlsafe(24)
    admin.call("POST", "/users", {
        "username": reviewer_name, "email": reviewer_name + "@example.test",
        "role": "admin", "password": reviewer_password,
    }, expected=201)
    reviewer = Session(endpoint, reviewer_name, reviewer_password)

    initial = admin.call("POST", "/bundle-backups", {}, expected=201)
    original = admin.call("GET", f"/bundle-backups/{initial['id']}/export")["snapshot"]["bundle"]
    require(original["bundle_hash"] == initial["bundle_hash"], "Initial backup exported a different bundle")
    wait_for_exact_runtime(admin, state_dir, node, initial["bundle_hash"], timeout)
    original_references = embedded_references(admin)
    require(bool(original_references), "Initial bundle did not report its embedded parser references")

    asset_id = "r8-live-sync-" + suffix
    route = "/config/known-keys/" + asset_id
    settings = {"keys": ["r8_fixture_key_" + suffix + "_" + str(index) for index in range(1500)]}
    draft = admin.call("POST", "/config/known-keys", {"id": asset_id, "name": "R8 fixture known keys", "config": settings}, expected=201)
    require(draft["state"] == "draft", "Fixture asset did not enter draft state")
    submitted = admin.call("POST", route + "/submit", {})
    require(submitted["state"] == "in_review", "Fixture asset did not enter review")
    approved = reviewer.call("POST", route + "/approve", {"reason": "Independently reviewed the synthetic key identifier"})
    require(
        approved["state"] == "approved" and approved["asset"]["payload"]["approved_by"] == reviewer_name,
        "Fixture asset approval was not independent",
    )
    published = admin.call("POST", route + "/publish", {})
    changed_hash = published["bundle_hash"]
    require(published["state"] == "active" and changed_hash != initial["bundle_hash"], "Publishing the new asset did not create a new bundle")
    require_approval_gate(admin, node, changed_hash)
    live_id = approve_rollout(reviewer, reviewer_name, published["rollout_proposal"]["id"], changed_hash, node)
    changed_bundle = wait_for_exact_runtime(admin, state_dir, node, changed_hash, timeout, live_id)
    require(("known-keys", asset_id) in bundle_content(changed_bundle), "The acknowledged publication omitted the fixture asset")
    revision = published["asset"]["revision"]
    history_path = metadata_dir / "known-keys" / f"{asset_id}--{revision:09d}.json"
    original_revision_bytes = history_path.read_bytes()

    restore = admin.call("POST", "/bundle-restores", {
        "backup_id": initial["id"], "expected_snapshot_hash": initial["snapshot_hash"],
        "reason": "Restore the exact pre-publication synthetic fixture bundle",
    }, expected=201)
    require(restore["state"] == "pending_approval" and restore["base_bundle_hash"] == changed_hash, "Restore did not pin the current controller generation")
    restored = reviewer.call("POST", f"/bundle-restores/{restore['id']}/approve", {
        "expected_snapshot_hash": restore["snapshot_hash"], "expected_base_revision": restore["base_revision"],
    })
    restored_hash = restored["desired_bundle_hash"]
    require(
        restored["state"] == "rollout_proposed" and restored["approved_by"] == reviewer_name
        and restored["desired_revision"] > 0 and restored_hash not in (changed_hash, initial["bundle_hash"]),
        "Restore did not record independent approval and create a new desired generation",
    )
    previous = admin.call("GET", f"/bundle-backups/{restored['pre_restore_backup_id']}/export")["backup"]
    require(previous["bundle_hash"] == changed_hash, "Pre-restore backup did not pin the last published bundle")
    require_approval_gate(admin, node, restored_hash)
    restore_live = approve_rollout(reviewer, reviewer_name, restored["rollout_proposal_id"], restored_hash, node)
    restored_bundle = wait_for_exact_runtime(admin, state_dir, node, restored_hash, timeout, restore_live)
    require(bundle_content(restored_bundle) == bundle_content(original), "Restored bundle does not have the exact original asset content")
    require(embedded_references(admin) == original_references, "Restore changed the classification or owning pack of an embedded parser reference")

    current = admin.call("GET", route)
    require(current["state"] == "revoked" and current["revision"] > revision, "Fixture asset was not revoked by a new revision")
    historic = json.loads(original_revision_bytes)
    require(
        history_path.read_bytes() == original_revision_bytes and historic["state"] == "active"
        and historic["payload"]["config"] == settings,
        "Restore rewrote or removed the previous published asset revision",
    )

    # Reproduce the user's actual NAPI record through an independently reviewed
    # publication and real client acknowledgement, after the rollback checks.
    def smtp_sample(index):
        fields = {"date": "202508" + str(11 + index), "timestamp": "080053105+0100",
                  "hostname": "aaa-gmailrgi" + str(9 + index).zfill(3), "service": "smtp",
                  "pid": str(3692 + index), "minor_pid": "0", "thread_id": str(140026854221568 + index),
                  "random_number": str(123456 + index), "event_type": "Note", "extra_tag1": "efgh",
                  "extra_tag2": "ijkl", "extra_tag3": "mnop", "event": "SieveRuleMsg",
                  "status": "failed", "reason": "not needed"}
        raw = "{date} {timestamp} {hostname} {service} {pid} {minor_pid} {thread_id} {random_number};{event_type};{extra_tag1};{extra_tag2};{extra_tag3};{event} status={status};reason={reason}".format(**fields)
        return {"raw": raw, "service": "smtp", "desired": fields}

    napi_id = "r8-smtp-client-" + suffix
    synthesis = admin.call("POST", "/assurance/napi/synthesize", {
        "id": napi_id, "name": "Synthetic SMTP full-output acceptance", "retain_review_examples": True,
        "discovery": [smtp_sample(0), smtp_sample(1)], "held_out": [smtp_sample(2)],
        "negative": ["not a structured mail record"],
    }, expected=201)
    require(synthesis["review_validation"]["status"] == "passed", "NAPI sample did not match exact expected output")
    admin.call("POST", "/parser-packs/" + napi_id + "/submit", {})
    reviewer.call("POST", "/assurance/parsers/" + napi_id + "/approve", {"reason": "Independent SMTP full output review"})
    napi_publish = admin.call("POST", "/assurance/parsers/" + napi_id + "/publish", {})
    napi_hash = napi_publish["bundle_hash"]
    require_approval_gate(admin, node, napi_hash)
    napi_live = approve_rollout(reviewer, reviewer_name, napi_publish["rollout_proposal"]["id"], napi_hash, node)
    wait_for_exact_runtime(admin, state_dir, node, napi_hash, timeout, napi_live)
    return {
        "initial_exact_acknowledgement": "passed",
        "packaged_known_key_publish_and_exact_acknowledgement": "passed",
        "bulk_known_keys_per_published_asset": len(settings["keys"]),
        "napi_smtp_independent_review_and_client_acknowledgement": "passed",
        "napi_smtp_parse_sample": smtp_sample(0),
        "independent_restore_and_exact_acknowledgement": "passed",
        "pre_restore_backup_and_revoked_revision_history": "passed",
        "embedded_reference_owner_parity": "passed",
        "embedded_reference_count": len(original_references),
        "published_bundle_hash": changed_hash,
        "restored_bundle_hash": restored_hash,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=150, help="maximum seconds per enrolment/acknowledgement phase")
    args = parser.parse_args()
    require(10 <= args.timeout <= 300, "Timeout must be between 10 and 300 seconds")
    require(Path("/.dockerenv").exists(), "This qualification may only run inside the disposable Docker controller fixture")
    config = json.loads(Path("/etc/nli/controller.json").read_text(encoding="utf-8"))
    require(config.get("storage_provider") == "local" and config.get("tls_cert"), "Qualification needs a TLS-enabled controller fixture with local metadata")
    port = int(config["listen_address"].rsplit(":", 1)[1])
    password = Path("/root/admin-password").read_text(encoding="utf-8").rstrip("\r\n")
    result = qualify(f"https://127.0.0.1:{port}", config, password, args.timeout)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except QualificationFailure as failure:
        print(f"Fixture qualification failed: {failure}", file=sys.stderr)
        sys.exit(1)
