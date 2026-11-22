# NLI Ver23 R8 — v23.0.0-8

R8 builds on the published R7 runtime and preserves its parser, synchronization,
backup/restore and installation protections. Installation modes remain 1–10;
there is no option 11. Existing published definitions continue running while a
replacement draft is edited, validated and independently reviewed.

## NAPI evidence and review

The NAPI workflow distinguishes transient synthesis from deliberately retained
redacted validation examples. A draft needs exact expected-output cases and a
passing validation of its saved revision before it can be submitted. Incomplete
drafts link directly to the validation editor. Missing evidence remains a
validation conflict, not a successful submission or an operational outage.
Requests remain in the audit chain; authorization and operational failures remain
actionable notifications. NUPIRE evaluation does not create another live parser.

The supplied numeric-prefix SMTP record now uses the same production header and
complete KV mapping as authored templates. This avoids ambiguous substring
inference for small fields such as `minor_pid="0"`. Full expected-output checks
cover the original 15 flat fields, changed values, multiword reasons, reordered
and dynamic KV pairs, and observed extra-tag ranges. Unsupported structures are
rejected rather than folded into another header field. New layouts still need
representative discovery and held-out examples. Catalog and Assurance now pin
the same submitted artifact checksum across all review-route combinations.

To create a NAPI draft, open Assurance Lab → NAPI Synthesis, supply separate
discovery and held-out records with the exact desired JSON, and optionally select
Save supplied redacted validation examples. Select Synthesize and validate draft.
Inspect the discovery, held-out, negative and saved-review results separately.
Open the complete validation editor if evidence is missing. Submit only after
the saved revision passes; an independent reviewer approves it before
publication. Approvals & Rollouts then gates client delivery, and Parser Fleet
Sync verifies the exact applied bundle hash. A test that confirms rejection of
incorrect output is not a successful parse.

## Bulk Known Key Catalog

An additional bulk import workflow accepts pasted names or supported text/CSV/JSON
files, previews validation and case-insensitive deduplication, and creates a
single revisioned draft through the existing review and publication lifecycle.
Existing single-key entry and advanced editing remain available. Imported names
are available to parsing after publication and exact client acknowledgement,
not merely after a successful browser upload. Valid dynamic keys remain named
even when absent from a known-key list. Limits and rejected input are shown in
the import preview.

## Human-readable AI guidance

Controller-verified guidance includes navigation, numbered steps, completion
checks and permission explanations. Simple-language questions can suggest an
appropriate workspace; explicit scope remains authoritative. An optional AI
provider selects only existing catalog operations. Invalid replies and provider
failures retain native guidance. This is versioned guidance, not model training.

## Login, approvals and qualification

Client Agent Management adds custom display names and named client groups stored
as revisioned controller metadata. Immutable enrollment IDs and hostnames remain
visible. Group targeting resolves to explicit node IDs for the proposed action;
editing a group later does not rewrite an already reviewed rollout target list.
Directory read/manage permissions and the existing action approval gates apply.
Groups support up to 10,000 members and 50,000 total memberships across 1,000
groups. Existing execution limits remain 1,000 clients per parser-sync request
and 4,096 per restart request; larger groups require explicitly reviewed batches.
Directory metadata is separate from parser-bundle snapshots. Revisions serialize
on the primary controller; this release does not implement distributed
multi-primary editing.

Login and read-only navigation must not publish drafts, approve rollouts or
create parser changes. New site-specific publications and newly enrolled targets
retain their explicit approval gates. Repeated navigation does not imply a new
approval is required for an unchanged applied generation.

The release qualification report records executed tests and finite limits.
Stress fixtures do not prove every possible log, UI mutation, network failure,
external AI model or live AWS configuration. Existing Supabase controller
credentials remain required; no automatic credential rotation or metadata purge
is introduced.
