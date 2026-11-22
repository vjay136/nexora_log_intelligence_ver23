# NLI release workflow

- User preference recorded 2026-11-21: prepare and verify release artifacts locally under `C:/Users/Vjay/Documents/vjay_all_projects/Nexora_Log_Intelligence/releases` before uploading/publishing the same bytes to GitHub.
- The authoritative baseline for Ver23 R4 (`v23.0.0-4`) is the existing local `releases/v22.19.1-0` folder. Do not substitute artifacts/runtime code from Ver23 R1–R3 or Ver22 releases 20/21.
- For R4, replicate that baseline with release identity, filenames and necessary filename-reference changes only. Preserve executable, parser, configuration and application behavior. Do not silently apply bug fixes or claim existing API/sync/authentication problems are resolved.
- Never put live credentials or installation transcripts containing secrets into releases or GitHub.
- Publication must upload the already-verified local artifacts; do not let a remote rebuild replace their bytes.

- R5 packaging regression (2026-11-22): write checksum/identity files as explicit UTF-8 bytes with LF line endings, preserve baseline executable modes and versioned directory layout in release tarballs, and run both actual installer `--verify-only` commands from a fresh Linux archive extraction before publication. Windows text readers normalize CRLF and do not prove Linux installer compatibility.

- R6 packaging regression: test a real legacy opposite-role RPM on the same node. Both roles own /usr/bin/nli; differing releases require a coordinated transaction using the matching local bundle. Never force-overwrite the shared file, silently erase a role, or enable an inactive counterpart during an upgrade. Preserve configuration, state and existing service enablement.
