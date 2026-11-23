# NLI Ver23 R9 — v23.0.0-9

R9 uses the published R8 source as its baseline and adds optional selective-input
and customer-output field policies. When no policy is enabled, existing R8 parsing and output
behavior is preserved. Installer modes 1–10 and coordinated mixed-role
updates remain in place.

## Selective Input Raw Log filter

Select records using literal keywords or bounded year, hostname, service,
event-type, log-level and event-name metadata. Values within one rule use OR;
rules within a policy use the selected ANY/ALL mode; multiple enabled input
policies use OR. The event name excludes a trailing parenthesized event code.
Disabled policies do not restrict input. Existing per-path selection filters still apply; a record must satisfy those filters and the enabled global policy.

The preview shows matched raw records and excluded counts before parsing. Parsing
the selected records requires a separate action. Live filtering occurs after
logical-record framing and before parser execution, quarantine and customer
delivery. Consumed excluded records advance the input cursor; changing the
policy later does not reconstruct those records. Original-source replay is
required if they are wanted again. Exclusion counters are separate from parser
failure counters.

## Remove Unwanted key names & its values in the JSON outputs

Enabled output policies remove the configured exact, case-sensitive root field
names from customer JSON. Enabled policies combine their removal sets. A dot in
a field name is literal, not a nested-path expression. Policies apply at customer
delivery boundaries after enrichment; internal health/audit records remain
available. The workspace previews before/after JSON and reports removed names. This removes
customer JSON fields; it does not remove raw source evidence, configuration,
transport metadata or Loki routing labels and is not a substitute for masking.

Each running agent pins one verified bundle generation. Activation uses the
existing coordinated drain/restart/readiness process. Already serialized durable
queue/WAL entries keep the generation under which they were produced; policies
do not retroactively rewrite queued payloads. Disabling a policy cannot restore
fields already removed from those payloads.

## Publication, compatibility and recovery

Drafts, local tests and previews do not modify live policy. Existing review,
publication, fleet approval and exact bundle acknowledgement gates apply.
Unsupported older clients must be upgraded before receiving policy-bearing
bundles. Invalid activation retains the previous generation. Both policy asset
classes participate in versioned parser-bundle backup and restore.

## Guidance and qualification

Provider connections try the validated numeric DNS addresses in order when a
route is unavailable. The complete DNS answer is still checked before dialing;
private-network restrictions, TLS verification, redirect refusal and request
deadlines remain in place.

The versioned AI guidance catalog describes the actual workspaces, controls,
approval steps and verification outcomes. Provider evaluation is distinct from
model training. Test credentials are read from private credential storage and
must never enter source, logs, screenshots or release artifacts.

The qualification report records measured throughput, sample outputs, stress
counts and executed scenarios. It does not promise zero latency, one million
records per second on arbitrary hardware, or universal correctness beyond the
tested contracts.
