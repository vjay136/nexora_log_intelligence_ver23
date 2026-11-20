# Nexora Log Intelligence Ver23 R3 — 23.0.0-3

Ver23 R3 upgrades Ver23 R2 (`23.0.0-2`). It restores the exact installation flow from Ver22 `22.19.1-0`, with identity-only substitutions for Ver23 installer names, artifact names and branding. R2's added new/existing-project questions, staged credential steps and controller-secret selection prompts are removed. The existing ten installation modes retain their original sequence.

Runtime fixes and role-aware uninstall preservation/purge behavior remain. Package identities, configuration/state paths and runtime semantic version `23.0.0` remain compatible; the RPM release advances to `3`. Switching to a different metadata project does not copy historical data automatically.

Restoring prompts is not a claim that Supabase HTTP 401 authentication failures are fixed. Authentication failures appeared in both the supplied Ver22.19 and R2 installation transcripts and require valid project credentials and registered controller authentication independently of the prompt flow.

Release qualification retains Go, race, browser, static, reproducibility and Rocky lifecycle gates. Upgrade/rollback uses genuine Ver23 R2 RPMs and the R2 schema from commit `4701a9d`. The verified original Ver22.19 source provenance remains unchanged. Published artifacts include controller/client RPMs, webapp ZIP, release archive and SHA256 checksums.
