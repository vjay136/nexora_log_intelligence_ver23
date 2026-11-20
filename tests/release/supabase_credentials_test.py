#!/usr/bin/env python3
"""Exercise actual credential selection/staging with synthetic data and no network.

Run as root on Linux (the release Docker fixture does this). Only temporary files
are touched. curl is a deterministic shell fixture; no Supabase/AWS calls occur.
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).parents[2]).resolve()
SOURCE = (ROOT / "scripts/setup-controller-rocky.sh").read_text().replace("\r\n", "\n")
SELECT_START = "# Supabase credentials are installation input"
SELECT_END = "# End Supabase credential selection."
STAGE_START = "# Stage candidate credentials before verification."
STAGE_END = "# End verified Supabase candidate preparation. Active files may now be saved."
SELECTION = SOURCE[SOURCE.index(SELECT_START):SOURCE.index(SELECT_END) + len(SELECT_END)]
STAGING = SOURCE[SOURCE.index(STAGE_START):SOURCE.index(STAGE_END) + len(STAGE_END)]
commit_start = SOURCE.index("\numask 077\nenv_tmp=", SOURCE.index(STAGE_END))
COMMIT = SOURCE[commit_start:SOURCE.index("\nif [[ $mode == 1 ]]; then", commit_start)]


def function(name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{.*?^\}", SOURCE, re.M | re.S)
    assert match, name
    return match.group() + "\n"


A = {"SUPABASE_URL": "https://fixture-a.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_a_" + "a" * 40,
     "NLI_SUPABASE_CONTROLLER_SECRET": "fixture-a-controller-" + "a" * 44, "SUPABASE_SECRET_KEY": "sb_secret_a_" + "a" * 40}
B = {"SUPABASE_URL": "https://fixture-b.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_b_" + "b" * 40,
     "NLI_SUPABASE_CONTROLLER_SECRET": "fixture-b-controller-" + "b" * 44, "SUPABASE_SECRET_KEY": "sb_secret_b_" + "b" * 40}
OVERRIDES = {"SUPABASE_URL": "NLI_SETUP_SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY": "NLI_SETUP_SUPABASE_PUBLISHABLE_KEY",
             "NLI_SUPABASE_CONTROLLER_SECRET": "NLI_SETUP_SUPABASE_CONTROLLER_SECRET", "SUPABASE_SECRET_KEY": "NLI_SETUP_SUPABASE_SECRET_KEY"}

SHELL = r'''set -eu
fail() { printf '%s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }
read() { printf '%s\n' "$*" >> "$READ_LOG"; builtin read "$@"; }
# Preserve actual install/mode behavior. Only the fixture's absent nli group is
# mapped to root; candidate/root credential ownership remains actual root:root.
install() {
  local args=() value
  while (($#)); do value=$1; shift; if [[ $value == -g && ${1:-} == nli ]]; then args+=(-g root); shift; else args+=("$value"); fi; done
  command install "${args[@]}"
}
chown() { local owner=$1; shift; [[ $owner != root:nli ]] || owner=root:root; command chown "$owner" "$@"; }
curl() {
  local url=${!#} public='' controller='' authorization='' item
  local args=("$@") index
  for ((index=0;index<${#args[@]};index++)); do
    if [[ ${args[index]} == -H ]]; then
      item=${args[index+1]}
      case $item in 'apikey: '*) public=${item#apikey: };; 'X-NLI-Controller-Secret: '*) controller=${item#X-NLI-Controller-Secret: };; 'Authorization: '*) authorization=${item#Authorization: };; esac
    fi
  done
  printf '%s\n' "$url" >> "$CURL_LOG"
  if [[ $url == */rest/v1/rpc/nli_health ]]; then
    [[ $public == "$EXPECTED_PUBLIC" ]] || { printf '{"error":"fixture key mismatch"}\n401'; return; }
    [[ -z $EXPECTED_CONTROLLER || $controller == "$EXPECTED_CONTROLLER" ]] || { printf '{"error":"fixture controller mismatch"}\n401'; return; }
    if [[ $public == sb_* ]]; then [[ -z $authorization ]] || return 88; else [[ $authorization == "Bearer $public" ]] || return 89; fi
    printf '{"status":"ok","schema_version":1}\n%s' "$RPC_STATUS"
  elif [[ $url == */storage/v1/bucket/* ]]; then
    [[ $public == "$EXPECTED_STORAGE" ]] || { printf 'fixture Storage apikey mismatch\n' >&2; return 22; }
    [[ -z $authorization ]] || { printf 'opaque server keys must not be sent as JWT Bearer tokens\n' >&2; return 22; }
    [[ $STORAGE_STATUS == 200 ]] || return 22
    printf '{"id":"%s","public":%s}' "${url##*/}" "$BUCKET_PUBLIC"
  else return 90; fi
}
storage_provider=supabase
supabase_url=''; supabase_public_key=''; supabase_controller_secret=''; supabase_storage_secret=''
enrollment_token=synthetic-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
audit_key=synthetic-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
csrf_key=synthetic-csrf-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
assurance_key=synthetic-assurance-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
artifact_public_keys=''; quarantine_key=''; quarantine_retention_enabled=false; admin_password=''
listen_address=127.0.0.1:12382; tls_cert=''; tls_key=''; force_secure=false; allow_insecure_remote=false
'''
HELPERS = "".join(function(name) for name in ["read_env", "valid_env_secret", "random_secret", "metadata_backend_change_ack"])


def parse_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.startswith("#"))


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "requires the root Linux release Docker fixture")
class Credentials(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.active = self.directory / "controller.env"
        self.credentials = self.directory / "credentials.env"
        self.config = self.directory / "controller.json"
        self.sql = self.directory / "bootstrap.sql"
        self.pending = pathlib.Path(str(self.credentials) + ".pending")
        self.write_record(self.active, A)
        self.write_record(self.credentials, A)
        self.config.write_text(json.dumps({"storage_provider": "supabase", "custom_setting": "must survive"}))
        self.sql.write_text("original verified SQL\n")
        self.before = {path: path.read_bytes() for path in [self.active, self.credentials, self.config, self.sql]}

    def write_record(self, path, values):
        path.write_text("PRESERVE_LINE=keep\n" + "".join(f"{key}={value}\n" for key, value in values.items()))
        path.chmod(0o600)

    def environment(self, selected=A, **settings):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("NLI_SETUP_", "SUPABASE_", "NLI_SUPABASE_"))}
        env.update(ENV_FILE=str(self.active), CREDENTIAL_FILE=str(self.credentials), CONFIG=str(self.config),
                   SUPABASE_SCHEMA_TEMPLATE=str(ROOT / "supabase/nli_schema.sql"), SUPABASE_BOOTSTRAP_FILE=str(self.sql),
                   STATE_DIR=str(self.directory / "state"), READ_LOG=str(self.directory / "reads.log"), CURL_LOG=str(self.directory / "curl.log"),
                   existing_metadata_provider="supabase", EXPECTED_PUBLIC=selected["SUPABASE_PUBLISHABLE_KEY"],
                   EXPECTED_CONTROLLER=selected["NLI_SUPABASE_CONTROLLER_SECRET"], EXPECTED_STORAGE=selected["SUPABASE_SECRET_KEY"],
                   RPC_STATUS="200", STORAGE_STATUS="200", BUCKET_PUBLIC="false")
        env.update(settings)
        return env

    def run_setup(self, selected=A, input_text="", commit=True, **settings):
        script = SHELL + HELPERS + SELECTION + "\n" + STAGING + (COMMIT if commit else "")
        result = subprocess.run(["bash", "-c", script], env=self.environment(selected, **settings), input=input_text,
                                capture_output=True, text=True, timeout=25)
        observed = result.stdout + result.stderr
        if (self.directory / "reads.log").exists(): observed += (self.directory / "reads.log").read_text()
        secrets = [value for record in [A, B] for key, value in record.items() if key != "SUPABASE_URL"]
        for path in [self.active, self.credentials, self.pending]:
            if path.exists(): secrets.extend(value for key, value in parse_env(path).items() if key in OVERRIDES and key != "SUPABASE_URL")
        for secret in secrets: self.assertNotIn(secret, observed, "credentials must never appear in prompts or diagnostics")
        return result

    def unchanged(self):
        for path, data in self.before.items(): self.assertEqual(path.read_bytes(), data, path.name)

    def overrides(self, values):
        return {OVERRIDES[key]: value for key, value in values.items()}

    def test_saved_same_project_keeps_hidden_defaults_and_private_modes(self):
        result = self.run_setup(NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"] + "/")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = parse_env(self.credentials)
        for key, value in A.items(): self.assertEqual(record[key], value)
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.credentials.stat().st_uid, 0)
        self.assertFalse(self.pending.exists())
        self.assertFalse(pathlib.Path(str(self.sql) + ".pending").exists())
        self.assertEqual(json.loads(self.config.read_text())["custom_setting"], "must survive")
        self.assertEqual((self.directory / "reads.log").read_text().count("-s -p"), 3)

    def test_fresh_existing_project_requires_explicit_secret_and_never_generates(self):
        self.active.write_text(""); self.credentials.unlink()
        result = self.run_setup(**{key: value for key, value in self.overrides(B).items() if key != "NLI_SETUP_SUPABASE_CONTROLLER_SECRET"}, NLI_SETUP_SUPABASE_PROJECT_MODE="existing")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required", result.stderr)
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.active.read_text(), "")

    def test_fresh_dynamic_inputs_accept_explicit_existing_project_choice(self):
        self.active.write_text(""); self.credentials.unlink()
        answers = "\n".join([B["SUPABASE_PUBLISHABLE_KEY"], "2", B["NLI_SUPABASE_CONTROLLER_SECRET"], B["SUPABASE_SECRET_KEY"]]) + "\n"
        result = self.run_setup(B, input_text=answers, NLI_SETUP_SUPABASE_URL=B["SUPABASE_URL"], existing_metadata_provider="")
        self.assertEqual(result.returncode, 0, result.stderr)
        for key, value in B.items(): self.assertEqual(parse_env(self.credentials)[key], value)
        self.assertEqual((self.directory / "reads.log").read_text().count("-s -p"), 3)

    def test_same_project_hidden_prompts_rotate_all_credentials(self):
        rotated = {"SUPABASE_URL": A["SUPABASE_URL"], "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_rotated_" + "r" * 40,
                   "NLI_SUPABASE_CONTROLLER_SECRET": "rotated-controller-" + "r" * 45, "SUPABASE_SECRET_KEY": "sb_secret_rotated_" + "r" * 40}
        answers = "\n".join(rotated[key] for key in ["SUPABASE_PUBLISHABLE_KEY", "NLI_SUPABASE_CONTROLLER_SECRET", "SUPABASE_SECRET_KEY"]) + "\n"
        result = self.run_setup(rotated, input_text=answers, NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for key, value in rotated.items(): self.assertEqual(parse_env(self.credentials)[key], value)
        self.assertEqual((self.directory / "reads.log").read_text().count("-s -p"), 3)

    def test_fresh_unattended_requires_mode_or_controller_override(self):
        self.active.write_text(""); self.credentials.unlink()
        settings = self.overrides(B); settings.pop("NLI_SETUP_SUPABASE_CONTROLLER_SECRET")
        result = self.run_setup(**settings)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("choose NLI_SETUP_SUPABASE_PROJECT_MODE", result.stderr)
        self.assertFalse(self.pending.exists())

    def test_explicit_new_project_generates_once_and_pending_is_resumable(self):
        self.active.write_text(""); self.credentials.unlink()
        settings = self.overrides(B); settings.pop("NLI_SETUP_SUPABASE_CONTROLLER_SECRET")
        first = self.run_setup(B, EXPECTED_CONTROLLER="", RPC_STATUS="401", NLI_SETUP_SUPABASE_PROJECT_MODE="new", **settings)
        self.assertNotEqual(first.returncode, 0)
        pending = parse_env(self.pending)
        secret = pending["NLI_SUPABASE_CONTROLLER_SECRET"]
        self.assertRegex(secret, r"^[0-9a-f]{64}$")
        self.assertEqual(self.pending.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.pending.stat().st_uid, 0)
        self.assertIn(hashlib.sha256(secret.encode()).hexdigest(), pathlib.Path(str(self.sql) + ".pending").read_text())
        second = self.run_setup(B, EXPECTED_CONTROLLER=secret, **settings)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(parse_env(self.credentials)["NLI_SUPABASE_CONTROLLER_SECRET"], secret)

    def test_new_url_does_not_inherit_previous_project_credentials(self):
        result = self.run_setup(B, NLI_SETUP_SUPABASE_URL=B["SUPABASE_URL"], NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key", result.stderr)
        self.unchanged()

    def test_mismatching_root_record_cannot_fill_missing_active_project_key(self):
        active = dict(A); active.pop("SUPABASE_PUBLISHABLE_KEY")
        self.write_record(self.active, active); self.write_record(self.credentials, B)
        before = {path: path.read_bytes() for path in self.before}
        result = self.run_setup(NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key", result.stderr)
        for path, data in before.items(): self.assertEqual(path.read_bytes(), data)

    def test_project_change_requires_acknowledgement(self):
        result = self.run_setup(B, **self.overrides(B))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("back up", result.stderr)
        self.unchanged()

    def test_terminal_project_change_requires_the_exact_confirmation(self):
        import pty
        script = SHELL + HELPERS + SELECTION + "\n" + STAGING + COMMIT
        for answer, expected_success in [("CANCEL", False), ("CHANGE-PROJECT", True)]:
            master, slave = pty.openpty()
            try:
                child = subprocess.Popen(["bash", "-c", script], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env=self.environment(B, **self.overrides(B)), text=True)
                os.close(slave); slave = None
                os.write(master, (answer + "\n").encode())
                stdout, stderr = child.communicate(timeout=25)
            finally:
                os.close(master)
                if slave is not None: os.close(slave)
            self.assertEqual(child.returncode == 0, expected_success, stderr)
            self.assertIn("Type CHANGE-PROJECT", stderr)
            for record in [A, B]:
                for key, value in record.items():
                    if key != "SUPABASE_URL": self.assertNotIn(value, stdout + stderr)
            if not expected_success: self.unchanged()

    def test_confirmed_project_change_backs_up_old_files_before_commit(self):
        result = self.run_setup(B, NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE="1", **self.overrides(B))
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = list(pathlib.Path(str(self.credentials) + ".project-backups").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
        for path, data in self.before.items():
            saved = backups[0] / path.name
            self.assertEqual(saved.read_bytes(), data)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        for key, value in B.items(): self.assertEqual(parse_env(self.credentials)[key], value)
        self.assertNotEqual(self.sql.read_bytes(), self.before[self.sql])

    def test_auth_failure_preserves_active_files_and_retains_private_candidate(self):
        for status in ["401", "403", "503"]:
            with self.subTest(status=status):
                result = self.run_setup(B, RPC_STATUS=status, NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE="1", **self.overrides(B))
                self.assertNotEqual(result.returncode, 0)
                self.unchanged()
                self.assertEqual(self.pending.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.pending.stat().st_uid, 0)
                for key, value in B.items(): self.assertEqual(parse_env(self.pending)[key], value)
                self.assertFalse(pathlib.Path(str(self.credentials) + ".project-backups").exists())

    def test_storage_auth_or_public_bucket_failure_preserves_active_files(self):
        for settings in [{"STORAGE_STATUS": "403"}, {"BUCKET_PUBLIC": "true"}]:
            with self.subTest(settings=settings):
                result = self.run_setup(B, NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE="1", **self.overrides(B), **settings)
                self.assertNotEqual(result.returncode, 0)
                self.unchanged()
                self.assertFalse(pathlib.Path(str(self.credentials) + ".project-backups").exists())

    def test_root_private_secret_file_and_legacy_public_key(self):
        secret_file = self.directory / "controller-input.secret"
        secret_file.write_text(A["NLI_SUPABASE_CONTROLLER_SECRET"] + "\n"); secret_file.chmod(0o600)
        legacy = dict(A, SUPABASE_PUBLISHABLE_KEY="eyJsyntheticLegacyAnonPublicKey" + "a" * 40)
        settings = self.overrides(legacy); settings.pop("NLI_SETUP_SUPABASE_CONTROLLER_SECRET")
        result = self.run_setup(legacy, NLI_SETUP_SUPABASE_CONTROLLER_SECRET_FILE=str(secret_file), **settings)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(parse_env(self.credentials)["SUPABASE_PUBLISHABLE_KEY"], legacy["SUPABASE_PUBLISHABLE_KEY"])

    def test_secret_file_rejects_unsafe_modes_symlinks_and_ambiguous_override(self):
        secret_file = self.directory / "controller-input.secret"
        secret_file.write_text(A["NLI_SUPABASE_CONTROLLER_SECRET"]); secret_file.chmod(0o644)
        result = self.run_setup(NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"], NLI_SETUP_SUPABASE_CONTROLLER_SECRET_FILE=str(secret_file))
        self.assertNotEqual(result.returncode, 0); self.unchanged()
        secret_file.chmod(0o600)
        link = self.directory / "secret-link"; link.symlink_to(secret_file)
        result = self.run_setup(NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"], NLI_SETUP_SUPABASE_CONTROLLER_SECRET_FILE=str(link))
        self.assertNotEqual(result.returncode, 0); self.unchanged()
        result = self.run_setup(NLI_SETUP_SUPABASE_CONTROLLER_SECRET_FILE=str(secret_file), **self.overrides(A))
        self.assertNotEqual(result.returncode, 0); self.unchanged()


if __name__ == "__main__":
    unittest.main(verbosity=2)
