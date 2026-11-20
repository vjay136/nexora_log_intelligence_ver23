#!/usr/bin/env python3
"""Original Ver22.19 credential/SQL wizard, synthetic offline root-Linux fixture.

The original flow saves before verification. These tests do not claim R2 staging,
rollback, project-isolation, or extra credential prompts. No real credentials,
cloud requests, AWS calls, or host services are used.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(sys.argv.pop(1) if len(sys.argv) > 1 else Path(__file__).parents[2]).resolve()
SOURCE = (ROOT / "scripts/setup-controller-rocky.sh").read_text()
start = SOURCE.index("if [[ $storage_provider == supabase ]]; then\ncurrent_supabase_url=")
SELECTION = SOURCE[start:SOURCE.index("\nif [[ -z $quarantine_retention_enabled ]]", start)]
begin = SOURCE.index("\numask 077\nenv_tmp=", start)
COMMIT = SOURCE[begin:SOURCE.index("\nif [[ $mode == 1 ]]; then", begin)]
begin = SOURCE.index("verify_supabase() {")
WIZARD = SOURCE[begin:SOURCE.index("\nsystemctl daemon-reload", begin)]


def function(name):
    found = re.search(r"^" + name + r"\(\) \{.*?^\}", SOURCE, re.M | re.S)
    assert found, name
    return found.group() + "\n"


HELPERS = "".join(function(name) for name in ["read_env", "valid_env_secret", "random_secret"])
A = {"SUPABASE_URL": "https://fixture-a.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_a_" + "a" * 40,
     "NLI_SUPABASE_CONTROLLER_SECRET": "fixture-controller-" + "a" * 44, "SUPABASE_SECRET_KEY": "sb_secret_a_" + "a" * 40}
B = {"SUPABASE_URL": "https://fixture-b.supabase.co", "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_b_" + "b" * 40,
     "NLI_SUPABASE_CONTROLLER_SECRET": "fixture-controller-" + "b" * 44, "SUPABASE_SECRET_KEY": "sb_secret_b_" + "b" * 40}
SHELL = r'''set -eu
fail() { printf '%s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }
read() { printf '%s\n' "$*" >> "$READ_LOG"; builtin read "$@"; }
install() {
  local args=() value
  while (($#)); do value=$1; shift; if [[ $value == -g && ${1:-} == nli ]]; then args+=(-g root); shift; else args+=("$value"); fi; done
  command install "${args[@]}"
}
chown() { local owner=$1; shift; [[ $owner != root:nli ]] || owner=root:root; command chown "$owner" "$@"; }
curl() {
  local url=${!#} public='' item index count status
  local args=("$@") statuses=()
  for ((index=0;index<${#args[@]};index++)); do
    if [[ ${args[index]} == -H ]]; then item=${args[index+1]}; case $item in 'apikey: '*) public=${item#apikey: };; esac; fi
  done
  [[ $url == */rest/v1/rpc/nli_health && $public == "$EXPECTED_PUBLIC" ]] || return 22
  count=$(grep -c '/rest/v1/rpc/nli_health' "$CURL_LOG" || true)
  IFS=, builtin read -r -a statuses <<< "$RPC_SEQUENCE"
  status=${statuses[count]:-${statuses[${#statuses[@]}-1]}}
  printf '%s\n' "$url" >> "$CURL_LOG"
  [[ $status == 200 ]] || return 22
  printf '{"status":"ok","schema_version":1}'
}
storage_provider=supabase; supabase_url=''; supabase_public_key=''; supabase_controller_secret=''; supabase_storage_secret=''
enrollment_token=synthetic-enrollment-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
audit_key=synthetic-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
csrf_key=synthetic-csrf-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
assurance_key=synthetic-assurance-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
artifact_public_keys=''; quarantine_key=''; quarantine_retention_enabled=false; admin_password=''
listen_address=127.0.0.1:12382; tls_cert=''; tls_key=''; force_secure=false; allow_insecure_remote=false
'''


def record(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.startswith("#"))


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "requires root Linux release Docker fixture")
class OriginalWizard(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.active = self.directory / "controller.env"; self.credentials = self.directory / "credentials.env"
        self.config = self.directory / "controller.json"; self.sql = self.directory / "bootstrap.sql"
        self.save(self.active, A); self.save(self.credentials, A)
        self.config.write_text(json.dumps({"storage_provider": "supabase", "custom_setting": "preserve"}))
        self.sql.write_text("previous SQL\n"); (self.directory / "curl.log").touch()

    def save(self, path, values):
        path.write_text("".join(key + "=" + value + "\n" for key, value in values.items())); path.chmod(0o600)

    def env(self, expected=A, **settings):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("NLI_SETUP_", "SUPABASE_", "NLI_SUPABASE_"))}
        env.update(ENV_FILE=str(self.active), CREDENTIAL_FILE=str(self.credentials), CONFIG=str(self.config),
            SUPABASE_SCHEMA_TEMPLATE=str(ROOT / "supabase/nli_schema.sql"), SUPABASE_BOOTSTRAP_FILE=str(self.sql),
            READ_LOG=str(self.directory / "read.log"), CURL_LOG=str(self.directory / "curl.log"),
            EXPECTED_PUBLIC=expected["SUPABASE_PUBLISHABLE_KEY"], RPC_SEQUENCE="200")
        env.update(settings); return env

    def no_leak(self, output):
        for values in [A, B, record(self.credentials) if self.credentials.exists() else {}]:
            for key, value in values.items():
                if value and key != "SUPABASE_URL": self.assertNotIn(value, output)

    def run_setup(self, expected=A, answers="", **settings):
        result = subprocess.run(["bash", "-c", SHELL + HELPERS + SELECTION + COMMIT + WIZARD],
            env=self.env(expected, **settings), input=answers, capture_output=True, text=True, timeout=25)
        self.no_leak(result.stdout + result.stderr); return result

    def test_original_saved_url_and_hidden_public_key_defaults(self):
        result = self.run_setup(answers="\n\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        for key, value in A.items(): self.assertEqual(record(self.credentials)[key], value)
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.credentials.stat().st_uid, 0)
        self.assertEqual(json.loads(self.config.read_text())["custom_setting"], "preserve")
        reads = (self.directory / "read.log").read_text()
        self.assertLess(reads.index("Supabase project URL"), reads.index("Supabase publishable/public key"))
        self.assertNotIn("NLI project initialization", reads); self.assertNotIn("CHANGE-PROJECT", reads)

    def test_original_fresh_flow_prompts_keys_and_generates_controller_secret(self):
        self.active.write_text(""); self.credentials.unlink()
        answers = "\n".join([B["SUPABASE_URL"], B["SUPABASE_PUBLISHABLE_KEY"], B["SUPABASE_SECRET_KEY"]]) + "\n"
        result = self.run_setup(B, answers=answers)
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = record(self.credentials); secret = saved["NLI_SUPABASE_CONTROLLER_SECRET"]
        self.assertRegex(secret, "^[0-9a-f]{64}$")
        for key in ["SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_SECRET_KEY"]: self.assertEqual(saved[key], B[key])
        sql = self.sql.read_text(); self.assertIn(hashlib.sha256(secret.encode()).hexdigest(), sql); self.assertNotIn(secret, sql)
        self.assertNotIn("__NLI_CONTROLLER_SECRET_SHA256__", sql)
        self.assertEqual(self.sql.stat().st_mode & 0o777, 0o600)
        self.assertFalse(Path(str(self.credentials) + ".pending").exists())

    def test_original_noninteractive_overrides_reuse_saved_controller_secret(self):
        result = self.run_setup(B, NLI_SETUP_SUPABASE_URL=B["SUPABASE_URL"], NLI_SETUP_SUPABASE_PUBLISHABLE_KEY=B["SUPABASE_PUBLISHABLE_KEY"], NLI_SETUP_SUPABASE_SECRET_KEY=B["SUPABASE_SECRET_KEY"])
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = record(self.credentials)
        self.assertEqual(saved["SUPABASE_URL"], B["SUPABASE_URL"])
        self.assertEqual(saved["NLI_SUPABASE_CONTROLLER_SECRET"], A["NLI_SUPABASE_CONTROLLER_SECRET"])

    def test_original_noninteractive_failure_is_honest_without_rollback_claim(self):
        for status in ["401", "403", "503"]:
            with self.subTest(status=status):
                result = self.run_setup(B, RPC_SEQUENCE=status, NLI_SETUP_SUPABASE_URL=B["SUPABASE_URL"], NLI_SETUP_SUPABASE_PUBLISHABLE_KEY=B["SUPABASE_PUBLISHABLE_KEY"], NLI_SETUP_SUPABASE_SECRET_KEY=B["SUPABASE_SECRET_KEY"])
                self.assertNotEqual(result.returncode, 0); self.assertIn("Supabase SQL Editor", result.stderr)
                # Ver22.19 saved before probing. Preserve this exact behavior,
                # rather than asserting the removed R2 staging guarantees.
                self.assertEqual(record(self.active)["SUPABASE_URL"], B["SUPABASE_URL"])
                self.assertEqual(record(self.credentials)["SUPABASE_URL"], B["SUPABASE_URL"])
                self.assertIn("listen_address", json.loads(self.config.read_text()))

    def test_original_terminal_sql_wizard_retries_once_then_reports_result(self):
        import pty
        for sequence, success in [("503,200", True), ("401,403", False)]:
            with self.subTest(sequence=sequence):
                (self.directory / "curl.log").write_text("")
                master, slave = pty.openpty()
                try:
                    child = subprocess.Popen(["bash", "-c", SHELL + HELPERS + SELECTION + COMMIT + WIZARD], stdin=slave,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env(RPC_SEQUENCE=sequence,
                        NLI_SETUP_SUPABASE_URL=A["SUPABASE_URL"], NLI_SETUP_SUPABASE_PUBLISHABLE_KEY=A["SUPABASE_PUBLISHABLE_KEY"], NLI_SETUP_SUPABASE_SECRET_KEY=A["SUPABASE_SECRET_KEY"]))
                    os.close(slave); slave = None; os.write(master, b"\n")
                    out, err = child.communicate(timeout=25)
                finally:
                    os.close(master)
                    if slave is not None: os.close(slave)
                self.no_leak(out + err); self.assertEqual(child.returncode == 0, success, err)
                self.assertIn("Press Enter after the SQL Editor reports success", err)
                self.assertEqual((self.directory / "curl.log").read_text().count("/rest/v1/rpc/nli_health"), 2)
                if not success: self.assertIn("schema verification still failed", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
