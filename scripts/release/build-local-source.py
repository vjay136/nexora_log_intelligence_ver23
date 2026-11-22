#!/usr/bin/env python3
"""CLI orchestration of the pinned source build from a Windows workspace.

Tests run separately before this command. This wraps the same production build
scripts as build.sh, reuses a disposable RPM tools container, and compares both
independent build outputs before placing files in the local release folder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]


def call(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def git(*args):
    return subprocess.check_output(["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT), *args], text=True).strip()


def env_file(path):
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#"))


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--module-cache", type=Path, required=True)
    parser.add_argument("--qualified", action="store_true", required=True,
                        help="Confirm separate Linux unit/vet/race/fuzz/browser qualification has passed")
    args = parser.parse_args()
    if git("status", "--porcelain"):
        raise SystemExit("Commit and freeze the source checkout before building")
    output, work = args.output.resolve(), args.scratch.resolve()
    for directory in (output, work):
        directory.mkdir(parents=True, exist_ok=True)
        if any(directory.iterdir()):
            raise SystemExit("Build directory must be empty: " + str(directory))
    revision, epoch = git("rev-parse", "HEAD"), git("show", "-s", "--format=%ct", "HEAD")
    identity = env_file(ROOT / "packaging/release.env")
    images = env_file(ROOT / "packaging/docker/images.env")
    module_cache = args.module_cache.resolve()
    for name in ("pass1", "pass2", "pass1-rpm", "pass2-rpm", "pass1-work", "pass2-work"):
        (work / name).mkdir()
    builder = "nli-source-rpm-" + uuid.uuid4().hex[:12]
    source_volume = "nli-source-" + revision[:16]
    source_mount = "type=volume,src=" + source_volume + ",dst=/src,readonly"
    common_env = ["-e", "SOURCE_REVISION=" + revision, "-e", "SOURCE_DATE_EPOCH=" + epoch]

    def go(command, destination=None, extra_env=None):
        command_args = ["docker", "run", "--rm", "--mount", source_mount,
                        "--mount", "type=bind,src=" + module_cache.as_posix() + ",dst=/go/pkg/mod",
                        "--mount", "type=volume,src=nli-r7-go-cache,dst=/root/.cache/go-build", "-w", "/src"]
        if destination:
            command_args += ["--mount", "type=bind,src=" + destination.as_posix() + ",dst=/out"]
        command_args += common_env
        for key, value in (extra_env or {}).items():
            command_args += ["-e", key + "=" + value]
        call(command_args + [images["GO_IMAGE"], "bash", "-c",
             "export PATH=/usr/local/go/bin:/usr/bin:/bin; set -euo pipefail; " + command])

    try:
        # Keep repeated Git/VCS scans on the Linux filesystem. Only committed
        # source enters the build, excluding untracked files and local settings.
        call(["docker", "run", "--rm", "--mount",
              "type=bind,src=" + ROOT.as_posix() + ",dst=/seed,readonly",
              "--mount", "type=volume,src=" + source_volume + ",dst=/src",
              images["GO_IMAGE"], "bash", "-c",
              "set -eu; git config --global --add safe.directory /seed; "
              "if ! test -d /src/.git; then git clone --no-local --depth=1 /seed /src; fi; "
              "test \"$(git -C /src rev-parse HEAD)\" = " + revision + "; "
              "test -z \"$(git -C /src status --porcelain)\""])
        call(["docker", "run", "-d", "--name", builder, "--mount", source_mount,
              "--mount", "type=bind,src=" + work.as_posix() + ",dst=/build",
              "--mount", "type=bind,src=" + output.as_posix() + ",dst=/artifacts",
              "-w", "/src", "--entrypoint", "/bin/bash", images["RPM_BUILD_IMAGE"],
              "-c", "while true; do sleep 60; done"])
        call(["docker", "exec", "-e", "ROOT=/src", builder, "bash", "-c",
              "bash /src/packaging/docker/install-rpm-tools.sh"])
        for build in ("pass1", "pass2"):
            print("Building and verifying source binaries: " + build, flush=True)
            go("git config --global --add safe.directory /src; bash scripts/release/preflight.sh; bash packaging/build-binaries.sh",
               work / build, {"ROOT": "/src", "OUTPUT_DIR": "/out", "NLI_SKIP_TESTS": "1"})
            print("Building RPMs and browser archives: " + build, flush=True)
            call(["docker", "exec", *common_env, "-e", "ROOT=/src", "-e", "BIN_ROOT=/build/" + build,
                  "-e", "OUTPUT_DIR=/build/" + build + "-rpm", "-e", "WORK_DIR=/build/" + build + "-work",
                  builder, "bash", "-c", "bash /src/packaging/build-rpms.sh"])
        first = {p.name: digest(p) for p in (work / "pass1-rpm").iterdir() if p.is_file()}
        second = {p.name: digest(p) for p in (work / "pass2-rpm").iterdir() if p.is_file()}
        if first != second:
            raise SystemExit("Independent source builds differ: " + ", ".join(k for k in first.keys() | second.keys() if first.get(k) != second.get(k)))
        for p in (work / "pass1-rpm").iterdir():
            if p.is_file():
                shutil.copyfile(p, output / p.name)
        go("go test ./internal/benchmarks -run='^$' -bench=. -benchmem -benchtime=100ms -count=1 > /out/BENCHMARKS.txt; "
           "go test ./parser-policy ./internal/mixedkv -run='^$' -bench=. -benchmem -benchtime=100ms -count=1 >> /out/BENCHMARKS.txt",
           output)
        go("go test ./internal/migration -run='^TestSample(LogCorpusFieldAccounting|FieldAccountingDuplicateSemantics)$' -count=1",
           output, {"NLI_FIELD_ACCOUNTING_REPORT": "/out/SAMPLE_FIELD_ACCOUNTING.json"})
        proof = {"release": "v" + identity["NLI_VERSION"] + "-" + identity["NLI_RELEASE"],
                 "source_revision": revision, "source_date_epoch": int(epoch), "runtime_recompiled": True,
                 "independent_builds": 2, "all_output_files_identical": True, "sha256": first,
                 "builder_images": images, "qualification": "performed separately before source freeze"}
        (output / "REPRODUCIBILITY.json").write_bytes((json.dumps(proof, indent=2) + "\n").encode("utf-8"))
        print(json.dumps(proof, indent=2), flush=True)
    finally:
        subprocess.run(["docker", "rm", "-f", builder], check=False)


if __name__ == "__main__":
    main()
