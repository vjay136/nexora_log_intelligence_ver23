# Nexora Log Intelligence Ver23 R2 — 23.0.0-2

Ver23 R2 upgrades Ver23 R1 (`23.0.0-1`) with dynamic Supabase credential setup. The runtime semantic version remains `23.0.0`; the RPM release advances to `2`.

Setup supports selecting a new or existing Supabase project and controller secret. Existing controller credentials remain the default for a configured project; operators can explicitly supply the project URL and protected keys appropriate to their environment. A new controller joining an existing project must use that project's registered controller secret. Incorrect replacement secrets cannot take over an existing registration.

Switching Supabase projects or metadata backends remains an explicit migration decision. Prior parser packs, templates, keys, users and metadata are **not copied automatically** into a different project. Back up and migrate the intended data before enabling the new target.

Installation modes remain 1 through 10. Existing package identities, configuration/state paths, TLS validation, role-aware uninstall preservation and explicit purge behavior remain compatible. No cloud project credentials are embedded in the release.

Release qualification retains the complete Go, race, browser, static, reproducibility and Rocky lifecycle gates. Upgrade/rollback qualification uses genuine Ver23 R1 RPMs from the Ver23 repository; schema qualification uses R1 commit `6e4867e`. The verified Ver22.19 source-baseline provenance remains unchanged. Published artifacts include both RPMs, webapp ZIP, release archive and SHA256 checksums.

Candidate credentials are verified before activation. Failed RPC authentication or private Storage verification preserves active credential/configuration files; confirmed project switches keep protected local backups. New pending credentials and generated SQL survive retries and are included in explicit controller purge cleanup. Public and server API-key prompts hide input. Modern Supabase keys use the supported `apikey` header without treating an opaque key as a JWT.

Fifteen offline installer tests exercise new/existing projects, saved values, hidden rotation, project isolation, interactive confirmation, protected secret files, failed verification, backups and output redaction. The uninstall matrix covers all ten installation modes with preserve/purge behavior.
