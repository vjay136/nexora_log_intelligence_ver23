# NLI Ver23 R10 — v23.0.0-10

R10 adds **COMMAND CENTER → Node Terminal** to the working R9 baseline. Existing parser, template, known-key, log-policy, rollout and restore workflows remain independent of terminal sessions. Installation modes 1–10 remain; there is no mode 11.

The optional local `nli-node-terminal` broker is shared by both RPM roles. It exposes only a Unix socket. Client sessions relay over the existing authenticated outbound NLI connection; browsers use the existing same-origin HTTPS API. No new public terminal port, SSH private key or database credential is required.

Terminal access is disabled by default. An administrator explicitly enables each host with `/usr/sbin/nli-node-terminal-setup --enable --role controller` or `--role client`. Root-owned mode-0600 host policy selects the dedicated operator account, canonical input-directory write access, and exact NLI service controls. A web request cannot request a root shell or change host privileges. The helper's `--disable` and explicit `--purge` options stop optional access.

The UI requires an administrator, the current NLI password and a session reason. Search/pagination supports large inventories while connecting only the explicitly selected node. Sessions have per-user/node/global limits, expiry, inactivity controls, bounded output and input sequencing. Navigation/signout closes access; uncertain input is never automatically replayed.

The terminal supports ordinary shell state, Enter, arrows, Ctrl+C, bounded paste, resizing and basic VT100 editor screens. Output is rendered as text; terminal OSC links and clipboard commands are ignored. Examples prepare text and require separate paste and Enter. Editing or deleting input files changes data, and service restarts can disconnect the session. Output/parser paths remain read-only to the operator.

Commands and terminal transcripts are ephemeral: they are not parser assets, Supabase backups, AI context or saved guidance evaluations. Explicit Copy visible output is available. Audit records identify actor, target, reason and session lifecycle without command/output contents. AI guidance catalog revision 4 explains the real navigation and controls without accessing the transcript.

See WEBAPP_OPERATOR_AND_PARSER_GUIDE.md for the demo procedure. Release qualification records describe actual observed tests; the feature does not claim unlimited terminal compatibility, production fleet capacity or a live AWS deployment.
