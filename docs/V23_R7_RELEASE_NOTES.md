# NLI Ver23 R7 — v23.0.0-7

R7 builds the corrected runtime from the retained v22.19.1 source foundation.
It preserves the existing installation modes and R6 coordinated mixed-role RPM
transaction. Controller installation has no option 11. Unlike R4–R6, this is a
functional release with newly compiled executables and updated browser assets.

## Parser activation and authoring

- Exact signed embedded parser copies are recognized as the built-ins already
  installed with the release. Changed protected definitions remain rejected.
  Built-ins are not duplicated as managed client add-ons.
- Parser Creation Workspace loads the real runtime inventory. Generated cases
  must contain expected output, and submitting a draft requires its saved,
  validated artifact checksum. Preview does not approve or deploy a parser.
- NAPI uses production-native mapping for JSON/KV candidates and compatible
  runtime types for regex candidates. Synthesis samples remain transient.
  Before review, the operator adds representative redacted validation cases,
  checks exact output, and saves the validated revision. A recovered parser
  missing extraction/evidence remains an editable draft. NUPIRE is an
  evaluation record linked to that parser, not another live parser instance.
- API errors retain their HTTP status and include a request ID and retry hint.
  Browser refreshes isolate optional metadata failures and preserve selection.
- Charts, utilization bars and text wrapping use stylesheet classes and bounded
  DOM style properties. They render under the existing strict CSP without
  permitting inline styles or scripts in the page policy.
- A local template/KV budget expiry receives one bounded fresh attempt while
  the caller context remains live. Both attempts remain in diagnostic telemetry.
  Malformed input, cancellation and persistent timeout remain fail-closed; the
  per-attempt and overall execution budgets are unchanged.
- Synchronized asset directories explicitly retain their protected group access
  even under the installer's restrictive umask. The `nli` agent can load the
  staged bundle before the client acknowledges it; failed readiness still
  restores the prior generation and does not report successful synchronization.

## Backup & Restore

The new workspace shows verified content-addressed published parser snapshots,
software release identity, exact asset revisions and hashes, and embedded pack
inventory. Controller materialization captures changed publications automatically;
failed captures remain explicitly visible and retry with bounded backoff.

Manual capture and export require parser management permission. Restore proposals
bind the selected snapshot and current publication, require an independent
approver, retain a pre-restore snapshot, and write new asset revisions. An
interrupted restore resumes through its durable journal; it does not expose a
partially rewritten parser bundle as the active runtime publication.

Controller restoration and fleet synchronization are separate states. Clients
must acknowledge the exact approved bundle hash before the UI reports applied.
Approval, stale acknowledgements, failed nodes and missing reports are displayed
explicitly. No fleet-wide completion is inferred from a controller-only success.

Snapshots cover published parser packs and seven supporting parser asset classes:
templates, KV configuration, known keys, regex patterns, static patterns,
projections and semantic extraction. They include approved regression examples
embedded in the exported parser definition. They exclude credentials, users,
node/global configuration and unrelated raw-log/Assurance history collections.
Snapshot limits are 3 MiB and 10,000 assets. Embedded pack inventory must match
the installed runtime when restoring; use the matching application release.

## AI Guidance & Revisions

The new workspace exposes a versioned catalog of real navigation, selected tabs
and verified operations. Optional provider evaluation can select only a valid
catalog action; invalid replies, timeouts and unavailable providers fall back to
controller guidance. Evaluation metadata and administrative revision annotations
retain catalog release/version/hash provenance without storing questions or
provider outputs. This is versioned guidance and evaluation, not model training.

## Qualification and operating limits

See the release qualification evidence for actual test counts and results.
Finite fixture, browser and stress tests do not establish correctness for every
possible record, network failure or production environment. Existing Supabase
authentication mismatches require the correct controller credential; R7 does not
rotate a project's secret or delete metadata automatically. Live recovered
drafts are not silently activated, and unknown deleted historical definitions
cannot be reconstructed without surviving evidence.
