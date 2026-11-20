"""Ver22.19 setup fidelity and original offline probe; no host changes."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
# Exact source provenance: baseline commit 77f95a9, v22.19.1-0.
baseline = {"setup-controller-rocky.sh": "4bc95ab2cfa504efe190ecb2f6f3070672d09ab2229a5eea52cabf6809a6ade1",
            "setup-supabase-rocky.sh": "1e66fdc046bfd596ab487fda0848f4bb768cb59adc033b25839800a3de2ee3ee"}
release = {"setup-controller-rocky.sh": "4033ba5dcfdb8c4c7a287b0446182bdbe0a3771c076969932348b43992d76a5b",
           "setup-supabase-rocky.sh": "1e66fdc046bfd596ab487fda0848f4bb768cb59adc033b25839800a3de2ee3ee"}
for name, expected in baseline.items():
    data = (root / "scripts" / name).read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data.replace(b"Ver23", b"Ver22")).hexdigest() == expected, name + ": functional baseline drift"
    assert hashlib.sha256(data).hexdigest() == release[name], name + ": unexpected source hash"
s = (root / "scripts/setup-controller-rocky.sh").read_text()
menu = re.findall(r"printf ' +([0-9]+)\) ([^']+)'", s)
assert [int(number) for number, _ in menu] == list(range(1, 11))
assert "Deployment mode [7]" in s and "deployment mode must be 1 through 10" in s
prompts = ["Deployment mode [7]", "Initial admin password (minimum 12 characters)", "Supabase project URL [",
           "Supabase publishable/public key [Enter keeps the packaged value]", "Supabase server-only secret key",
           "Press Enter after the SQL Editor reports success"]
positions = [s.index(prompt) for prompt in prompts]
assert positions == sorted(positions), "original prompt order changed"
for extra in ["CHANGE-PROJECT", "NLI project initialization", "supabase_pending_file", "saved_supabase_value", "supabase_auth_rejected"]:
    assert extra not in s, "R2-only setup behavior remains: " + extra
probe = s.split("verify_supabase() {", 1)[1].split("\n}\n", 1)[0]
bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
assert bash
header = '''python3() { "$NLI_TEST_PYTHON" "$@"; }
curl() { [[ $HTTP_STATUS == 200 ]] || return 22; printf '%s' "$RPC_BODY"; }
'''
for status, body, expected in [("200", '{"status":"ok","schema_version":1}', 0),
    ("401", "{}", 1), ("403", "{}", 1), ("404", "{}", 1), ("503", "{}", 1),
    ("200", '{"status":"bad","schema_version":1}', 1), ("200", '{"status":"ok","schema_version":99}', 1), ("200", "not-json", 1)]:
    script = header + "verify_supabase() {" + probe + "\n}\n"
    script += "supabase_public_key=synthetic; supabase_controller_secret=synthetic; supabase_url=https://fixture.supabase.co\n"
    script += "verify_supabase >/dev/null 2>&1; printf '%s' \"$?\""
    result = subprocess.run([bash, "-c", script], capture_output=True, text=True,
        env=dict(os.environ, NLI_TEST_PYTHON=sys.executable.replace("\\", "/"), HTTP_STATUS=status, RPC_BODY=body))
    assert result.returncode == 0 and result.stdout == str(expected), (status, result.stdout, result.stderr)
print("Ver22.19 setup fidelity: PASS (baseline hashes, branding-only equality, ten modes, ordered prompts, original RPC probe)")
