# NLI release workflow

- User preference recorded 2026-11-21: prepare and verify release artifacts locally under `C:/Users/Vjay/Documents/vjay_all_projects/Nexora_Log_Intelligence/releases` before uploading/publishing the same bytes to GitHub.
- The authoritative baseline for Ver23 R4 (`v23.0.0-4`) is the existing local `releases/v22.19.1-0` folder. Do not substitute artifacts/runtime code from Ver23 R1–R3 or Ver22 releases 20/21.
- For R4, replicate that baseline with release identity, filenames and necessary filename-reference changes only. Preserve executable, parser, configuration and application behavior. Do not silently apply bug fixes or claim existing API/sync/authentication problems are resolved.
- Never put live credentials or installation transcripts containing secrets into releases or GitHub.
- Publication must upload the already-verified local artifacts; do not let a remote rebuild replace their bytes.
