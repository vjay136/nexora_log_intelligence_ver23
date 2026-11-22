-- Read-only manager evidence: no credentials or parser payload bodies.
-- All retained revisions, including drafts and tombstones, remain visible here.
select collection, document_id, revision, state, deleted,
       payload->>'version' as parser_definition_version,
       sha256, created_by, created_at, updated_at
from public.nli_documents
where collection in (
  'parser-packs','templates','kv-config','known-keys','projections',
  'static-patterns','regex-patterns','semantic-extraction'
)
order by collection, document_id, revision desc;

-- Latest reported client acknowledgement. This is not a live availability test.
select distinct on(document_id) document_id, revision, updated_at,
       payload->>'desired_asset_bundle_hash' as desired_bundle_hash,
       payload->>'active_asset_bundle_hash' as applied_bundle_hash,
       payload->>'asset_sync_status' as sync_status,
       payload->>'asset_drifted' as asset_drifted
from public.nli_documents
where collection='fleet-sync' and not deleted
order by document_id, revision desc;
