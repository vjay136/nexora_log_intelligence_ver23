# Nexora Log Intelligence Ver23 R1 — 23.0.0-1

This major release starts from Ver22 `22.19.1-0`, source commit `77f95a9`, in the independent `vjay136/nexora_log_intelligence_ver23` repository. It does not include the subsequent Ver22.20 or Ver22.21 release branches.

Public installer and distribution artifact names use Ver23. The RPM identities `nli-client` and `nli-controller-agent`, services, `/etc/nli` configuration, state paths and installed WebView directory stay compatible for upgrades without discarding existing data. The existing installation choices remain modes 1 through 10.

Reconfiguring transport preserves the configured metadata backend and Supabase project. Intentional metadata backend changes require explicit acknowledgment after operator backup and migration. Supabase bootstrap retains the registered controller secret; incorrect replacement secrets fail without taking over the project.

The eight sealed, reviewed ParserPacks shipped in the exact Ver22.19 client RPM are now registered in the controller catalog when their IDs have no existing history. Their original definitions and regression cases are unchanged. Existing revisions and deliberate deletions take precedence. Modified protected pack IDs remain rejected. Bundles containing these packs require Ver23 clients; incompatible clients report an upgrade requirement instead of failing during activation.

Successful validation of those exact immutable product definitions is reused within the controller process. Concurrent requests receive separate decoded copies, and cancelled requests cannot invalidate the shared proof. Changed definitions and customer-authored packs still undergo full validation.

Controller restarts carry a new instance identifier so the Webapp can accept a fresh snapshot even when its revision counter restarts. Backend authentication and schema failures return actionable diagnostics without silently replacing the catalog or signing users out. Controller and client retain ten verified prior bundles for inspection and recovery; retention does not automatically activate an older generation.

Saved header/KV composition separates its bounded metadata-fetch budget from the existing parsing deadline. A slow reference lookup no longer consumes the parsing allowance or masquerades as a missing revision. Backend failures return service diagnostics; genuinely missing or invalid selections remain input errors. Analysis admission limits and extraction bounds remain enforced.

Reset controls cover all 52 primary workspaces and their inner tabs. Reset clears local inputs, drafts, filters and results, cancels pending previews, and preserves published records, user roles, favorites and live synchronization.

Uninstall offers two explicit behaviors: normal removal preserves local data for reinstall, while `--purge` removes the selected role's local configuration, identity, keys, queues and state. Both remove NLI-owned execution services and edge configuration. Shared files stay available to another installed NLI role; externally managed certificates, source logs and Supabase records are preserved. Client purge confirmation occurs before package removal.

Recovery preserves surviving Supabase records and separately imported customer exports. A release RPM contains shipped product definitions, not every customer-created record. Exported customer definitions lacking retained validation evidence stay drafts until validated and approved; no missing approval history is invented. Reinstalling a node after a state purge requires its original project, controller identity and enrollment settings.

See [installation and configuration](INSTALLATION_AND_CONFIGURATION.md) for supported installation and metadata preservation procedures. Release qualification evidence and SHA256SUMS accompany the published build; only completed verification gates may be reported as passed.
