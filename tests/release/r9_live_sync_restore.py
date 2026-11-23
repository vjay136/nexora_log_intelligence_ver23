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


def qualify(endpoint, config, password, timeout, checkpoint_dir=None):
    state_dir = Path(config["state_dir"])
    metadata_dir = Path(config.get("storage_dir") or state_dir / "metadata")
    admin = Session(endpoint, "admin", password)
    node = wait_for_single_client(admin, timeout)
    suffix = secrets.token_hex(4)
    reviewer_name = "r9-review-" + suffix
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

    # Exercise real independently reviewed policy generations before the
    # existing known-key/NAPI checks. A shared fixture checkpoint pauses at
    # each exact ACK so the driver tests the actual installed client bytes.
    rows = [
        "20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C4:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
        "20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerEHLO(2001/4) id=6864BD5E047384C4:domain=server035.mx.internal:host=11.22.33.44",
        "20250812 130035122+0100 aaa-gmailrgo009 smtp 3609 0 140293768701696 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C3:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
    ]
    # The baseline generic JSON parser uses numeric PID/thread fields.
    before_json = {"event": "r9-packaged-proof", "pid": 3609, "thread_id": 140293780948736, "keep": "exact retained value"}
    after_json = {key: value for key, value in before_json.items() if key not in ("pid", "thread_id")}
    input_settings = {"enabled": True, "match_mode": "any", "rules": [
        {"field": "event", "operator": "equals", "values": ["SmtpServerEHLO"], "case_sensitive": True},
        {"field": "keyword", "operator": "prefix", "values": ["{"], "case_sensitive": True},
    ]}
    output_settings = {"enabled": True, "fields": ["pid", "thread_id"]}
    policy_ids = {kind: "r9-policy-" + kind + "-" + suffix for kind in ("selective-input", "output-fields")}
    policy_history = {}
    policy_hashes = {}
    checkpoint_proofs = []

    def deploy_policy(kind, settings, modify=False):
        policy_route = "/config/" + kind + "/" + policy_ids[kind]
        payload = {"id": policy_ids[kind], "name": "R9 packaged " + kind, "config": settings}
        if modify:
            current = admin.call("GET", policy_route)
            payload.pop("id")  # The exact PUT schema takes its identity from the URL.
            payload["expected_revision"] = current["revision"]
            admin.call("PUT", policy_route, payload)
        else:
            admin.call("POST", "/config/" + kind, payload, expected=201)
        admin.call("POST", policy_route + "/submit", {})
        approval = reviewer.call("POST", policy_route + "/approve", {"reason": "Independent packaged optional-policy review"})
        require(approval["asset"]["payload"]["approved_by"] == reviewer_name, "Policy review was not independent")
        published = admin.call("POST", policy_route + "/publish", {})
        acknowledge(published)
        return published

    def acknowledge(published):
        digest = published["bundle_hash"]
        require_approval_gate(admin, node, digest)
        live = approve_rollout(reviewer, reviewer_name, published["rollout_proposal"]["id"], digest, node)
        return wait_for_exact_runtime(admin, state_dir, node, digest, timeout, live)

    def checkpoint(name, enabled):
        runtime = admin.call("GET", "/parser-sync/runtime")
        digest = runtime["bundle"]["desired_hash"]
        policy_hashes[name] = digest
        if checkpoint_dir is None:
            return
        directory = Path(checkpoint_dir)
        directory.mkdir(parents=True, exist_ok=True)
        phase = {"phase": name, "bundle_hash": digest, "input_enabled": enabled,
                 "raw_rows": rows, "json_raw": json.dumps(before_json),
                 "json_expected": after_json if enabled else before_json}
        temporary = directory / "phase.tmp"
        temporary.write_text(json.dumps(phase), encoding="utf-8")
        temporary.replace(directory / "phase.json")
        proof_path = directory / (name + ".done.json")
        proof = wait_for("packaged client CLI proof " + name, timeout,
                         lambda: json.loads(proof_path.read_text(encoding="utf-8")) if proof_path.exists() else None)
        require(proof.get("phase") == name and proof.get("bundle_hash") == digest and proof.get("passed") is True,
                "Driver did not prove the same acknowledged client policy generation")
        checkpoint_proofs.append(proof)

    def restore_backup(backup):
        base = admin.call("GET", "/parser-sync/runtime")["bundle"]["desired_hash"]
        proposal = admin.call("POST", "/bundle-restores", {"backup_id": backup["id"],
            "expected_snapshot_hash": backup["snapshot_hash"], "reason": "Restore packaged policy qualification generation"}, expected=201)
        require(proposal["state"] == "pending_approval" and proposal["base_bundle_hash"] == base, "Policy restore bypassed its base generation")
        restored_policy = reviewer.call("POST", "/bundle-restores/" + proposal["id"] + "/approve", {
            "expected_snapshot_hash": proposal["snapshot_hash"], "expected_base_revision": proposal["base_revision"]})
        digest = restored_policy["desired_bundle_hash"]
        require_approval_gate(admin, node, digest)
        live = approve_rollout(reviewer, reviewer_name, restored_policy["rollout_proposal_id"], digest, node)
        return wait_for_exact_runtime(admin, state_dir, node, digest, timeout, live)

    for kind, settings_value in (("selective-input", input_settings), ("output-fields", output_settings)):
        publication = deploy_policy(kind, settings_value)
        revision_path = metadata_dir / kind / f"{policy_ids[kind]}--{publication['asset']['revision']:09d}.json"
        policy_history[kind] = (revision_path, revision_path.read_bytes())
    raw_preview = admin.call("POST", "/policies/input/preview", {"raw": "\r\n".join(rows), "use_live": True, "parse": False})
    require(raw_preview["matched_raw"] == [rows[1]] and raw_preview["accepted_count"] == 1
            and raw_preview["excluded_count"] == 2 and raw_preview["results"] == [] and not raw_preview["parse_requested"],
            "Published input raw preview did not preserve exactly one EHLO record without parsing")
    # JSON is a deliberately admitted second rule so output policy proof is
    # independent of mail-family parser output details.
    explicit_parse = admin.call("POST", "/policies/input/preview", {"raw": json.dumps(before_json), "use_live": True, "parse": True})
    require(explicit_parse["parse_requested"] and explicit_parse["results"][0]["passed"]
            and explicit_parse["results"][0]["after"] == after_json, "Explicit matched parsing did not apply published output removal")
    output_preview = admin.call("POST", "/policies/output/preview", {"raw": json.dumps(before_json), "use_live": True})
    require(output_preview["before"] == [before_json] and output_preview["after"] == [after_json], "Published exact-root output preview changed retained fields")
    enabled_backup = admin.call("POST", "/bundle-backups", {}, expected=201)
    enabled_bundle = admin.call("GET", f"/bundle-backups/{enabled_backup['id']}/export")["snapshot"]["bundle"]
    checkpoint("enabled", True)
    for kind, settings_value in (("selective-input", input_settings), ("output-fields", output_settings)):
        deploy_policy(kind, {**settings_value, "enabled": False}, modify=True)
    checkpoint("disabled", False)
    restored_policy_bundle = restore_backup(enabled_backup)
    require(bundle_content(restored_policy_bundle) == bundle_content(enabled_bundle), "Policy restore changed backed-up payloads")
    for kind, (revision_path, original_bytes) in policy_history.items():
        require(revision_path.read_bytes() == original_bytes, "Policy restore modified historical published bytes: " + kind)
    checkpoint("restored", True)
    for kind in policy_ids:
        revoked = admin.call("POST", "/config/" + kind + "/" + policy_ids[kind] + "/revoke", {"reason": "Packaged revoke pass-through qualification"})
        acknowledge(revoked)
    checkpoint("revoked", False)
    restored_original = restore_backup(initial)
    require(bundle_content(restored_original) == bundle_content(original), "Policy qualification did not restore the original baseline before NAPI")

    asset_id = "r9-live-sync-" + suffix
    route = "/config/known-keys/" + asset_id
    settings = {"keys": ["r9_fixture_key_" + suffix + "_" + str(index) for index in range(1500)]}
    draft = admin.call("POST", "/config/known-keys", {"id": asset_id, "name": "R9 fixture known keys", "config": settings}, expected=201)
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

    napi_id = "r9-smtp-client-" + suffix
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
        "optional_policy_lifecycle_restore_and_exact_acknowledgement": "passed",
        "policy_generation_hashes": policy_hashes,
        "packaged_client_policy_checkpoint_proofs": checkpoint_proofs,
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
    parser.add_argument("--checkpoint-dir", type=Path, help="shared disposable fixture directory for installed-client CLI proof")
    args = parser.parse_args()
    require(10 <= args.timeout <= 300, "Timeout must be between 10 and 300 seconds")
    require(Path("/.dockerenv").exists(), "This qualification may only run inside the disposable Docker controller fixture")
    config = json.loads(Path("/etc/nli/controller.json").read_text(encoding="utf-8"))
    require(config.get("storage_provider") == "local" and config.get("tls_cert"), "Qualification needs a TLS-enabled controller fixture with local metadata")
    port = int(config["listen_address"].rsplit(":", 1)[1])
    password = Path("/root/admin-password").read_text(encoding="utf-8").rstrip("\r\n")
    result = qualify(f"https://127.0.0.1:{port}", config, password, args.timeout, args.checkpoint_dir)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except QualificationFailure as failure:
        print(f"Fixture qualification failed: {failure}", file=sys.stderr)
        sys.exit(1)
