package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nexora.local/nli-v20/internal/fleet"
	"nexora.local/nli-v20/internal/logpolicy"
	"nexora.local/nli-v20/internal/middleware"
)

func isLogPolicyCollection(collection string) bool {
	return collection == "selective-input" || collection == "output-fields"
}

func validateLogPolicyConfig(collection string, config map[string]any) error {
	encoded, err := json.Marshal(config)
	if err != nil || config == nil {
		return errors.New("a policy configuration object is required")
	}
	if collection == "selective-input" {
		var policy logpolicy.InputConfig
		if err = strictJSON(encoded, &policy); err == nil {
			err = logpolicy.ValidateInput(policy)
		}
		return err
	}
	var policy logpolicy.OutputConfig
	if err = strictJSON(encoded, &policy); err == nil {
		err = logpolicy.ValidateOutput(policy)
	}
	return err
}

func logPoliciesFromBundle(bundle parserAssetBundle) (*logpolicy.Set, error) {
	inputs := []logpolicy.InputConfig{}
	outputs := []logpolicy.OutputConfig{}
	for _, asset := range bundle.Assets {
		if !isLogPolicyCollection(asset.AssetClass) {
			continue
		}
		var envelope struct {
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(asset.Payload, &envelope); err != nil || len(envelope.Config) == 0 {
			return nil, fmt.Errorf("invalid policy asset %s/%s", asset.AssetClass, asset.AssetID)
		}
		if asset.AssetClass == "selective-input" {
			var policy logpolicy.InputConfig
			if err := strictJSON(envelope.Config, &policy); err != nil {
				return nil, fmt.Errorf("invalid input policy %s: %w", asset.AssetID, err)
			}
			policy.ID = asset.AssetID
			inputs = append(inputs, policy)
		} else {
			var policy logpolicy.OutputConfig
			if err := strictJSON(envelope.Config, &policy); err != nil {
				return nil, fmt.Errorf("invalid output policy %s: %w", asset.AssetID, err)
			}
			policy.ID = asset.AssetID
			outputs = append(outputs, policy)
		}
	}
	return logpolicy.Compile(inputs, outputs)
}

// Review checks the prospective aggregate, not merely the new document. The
// effective prior publication remains live while this candidate is reviewed.
func (s *Server) validateProjectedLogPolicies(ctx context.Context, collection, id string, payload map[string]any) error {
	bundle := parserAssetBundle{SchemaVersion: 1}
	for _, kind := range []string{"selective-input", "output-fields"} {
		docs, err := s.listEffectiveParserAssets(ctx, kind)
		if err != nil {
			return err
		}
		for _, doc := range docs {
			if doc.State != "active" || doc.Deleted || kind == collection && doc.ID == id {
				continue
			}
			bundle.Assets = append(bundle.Assets, parserBundleAsset{AssetClass: kind, AssetID: doc.ID, Payload: doc.Payload})
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	bundle.Assets = append(bundle.Assets, parserBundleAsset{AssetClass: collection, AssetID: id, Payload: encoded})
	_, err = logPoliciesFromBundle(bundle)
	return err
}

func bundleRequiresLogPolicies(bundle parserAssetBundle) bool {
	for _, asset := range bundle.Assets {
		if isLogPolicyCollection(asset.AssetClass) {
			return true
		}
	}
	return false
}

func nodeSupportsLogPolicies(node *fleet.Node) bool {
	if node == nil {
		return false
	}
	for _, capability := range node.FeatureCapabilities {
		if capability == logpolicy.Capability {
			return true
		}
	}
	return false
}

func parserClientSupportsLogPolicies(node *fleet.Node, bundle parserAssetBundle) bool {
	return !bundleRequiresLogPolicies(bundle) || nodeSupportsLogPolicies(node)
}

func parserSyncPolicyClientBlocker(node *fleet.Node, bundle parserAssetBundle, minimum string, acknowledged bool, state map[string]any) (string, string) {
	if !parserClientSupportsLogPolicies(node, bundle) {
		return "client_upgrade_required", "Upgrade the parsing agent and client control service to R9 or newer. The actual parsing agent must advertise log-policies-v1 before this bundle can be delivered or acknowledged."
	}
	return parserSyncClientBlocker(node, minimum, acknowledged, state)
}

// The last verified, materialized publication is a recovery source if metadata
// is temporarily unavailable. Missing state is the R8 no-policy baseline;
// corrupt state is never interpreted as permission to bypass active policies.
func (s *Server) persistedLogPolicies() (*logpolicy.Set, error) {
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "parser-assets", "bundle.json"))
	if errors.Is(err, os.ErrNotExist) {
		return logpolicy.Compile(nil, nil)
	}
	if err != nil {
		return nil, err
	}
	var bundle parserAssetBundle
	if json.Unmarshal(data, &bundle) != nil {
		return nil, errors.New("materialized policy publication is invalid")
	}
	digest, _, err := bundleDigest(bundle)
	if err != nil || digest != bundle.BundleHash {
		return nil, errors.New("materialized policy publication hash is invalid")
	}
	return logPoliciesFromBundle(bundle)
}

type logPolicyPreviewRequest struct {
	Raw      string         `json:"raw"`
	Records  []string       `json:"records,omitempty"`
	Config   map[string]any `json:"config,omitempty"`
	UseLive  bool           `json:"use_live"`
	Parse    bool           `json:"parse"`
	Service  string         `json:"service,omitempty"`
	ParserID string         `json:"parser_id,omitempty"`
}

func logPolicyPreviewRecords(input logPolicyPreviewRequest) ([]string, error) {
	if input.Raw != "" && len(input.Records) > 0 {
		return nil, errors.New("provide raw text or framed records, not both")
	}
	rows := input.Records
	if len(rows) == 0 {
		// Remove record delimiters, never trim or otherwise rewrite each record.
		normal := strings.ReplaceAll(strings.ReplaceAll(input.Raw, "\r\n", "\n"), "\r", "\n")
		rows = strings.Split(normal, "\n")
		if len(rows) > 0 && rows[len(rows)-1] == "" {
			rows = rows[:len(rows)-1]
		}
	}
	if len(rows) == 0 || len(rows) > 10000 {
		return nil, errors.New("provide 1..10000 records")
	}
	bytes := 0
	for _, row := range rows {
		bytes += len(row)
		if len(row) > logpolicy.MaxRawBytes {
			return nil, errors.New("a record exceeds 1 MiB")
		}
	}
	if bytes == 0 || bytes > logpolicy.MaxRawBytes {
		return nil, errors.New("preview raw input must be 1 byte to 1 MiB")
	}
	return rows, nil
}

func (s *Server) handleLogPolicyPreview(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	if path == "status" {
		if r.Method != http.MethodGet {
			jsonError(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if s.authorize(w, r, middleware.PermissionReadParsers) == nil {
			return
		}
		bundle, err := s.buildActiveParserBundle(r.Context())
		if err != nil {
			jsonError(w, "published policy state unavailable", http.StatusServiceUnavailable)
			return
		}
		assets := []map[string]any{}
		for _, asset := range bundle.Assets {
			if isLogPolicyCollection(asset.AssetClass) {
				assets = append(assets, map[string]any{"asset_class": asset.AssetClass, "id": asset.AssetID, "revision": asset.Revision, "sha256": asset.SHA256})
			}
		}
		set, err := logPoliciesFromBundle(bundle)
		if err != nil {
			jsonError(w, "published policy state is invalid", http.StatusServiceUnavailable)
			return
		}
		jsonOK(w, map[string]any{"bundle_hash": bundle.BundleHash, "assets": assets, "input_enabled": set.InputEnabled(), "output_enabled": set.OutputEnabled(), "required_capability": logpolicy.Capability, "synchronization": "Verify exact client acknowledgements in Parser Fleet Sync; publication alone does not prove client application."})
		return
	}
	if path != "input/preview" && path != "output/preview" {
		jsonError(w, "unknown policy operation", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.authorize(w, r, middleware.PermissionParsePreview) == nil {
		return
	}
	var input logPolicyPreviewRequest
	if decodeJSON(r, &input, 2<<20) != nil {
		jsonError(w, "invalid policy preview request", http.StatusBadRequest)
		return
	}
	if input.ParserID == "auto" {
		input.ParserID = ""
	}
	rows, err := logPolicyPreviewRecords(input)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var policies *logpolicy.Set
	bundleHash, scope := "", "draft"
	if input.UseLive {
		bundle, readErr := s.buildActiveParserBundle(r.Context())
		if readErr != nil {
			jsonError(w, "published policy state unavailable", http.StatusServiceUnavailable)
			return
		}
		policies, err = logPoliciesFromBundle(bundle)
		bundleHash = bundle.BundleHash
		scope = "live"
	} else {
		collection := "selective-input"
		if path == "output/preview" {
			collection = "output-fields"
		}
		if err = validateLogPolicyConfig(collection, input.Config); err == nil {
			encoded, _ := json.Marshal(input.Config)
			if collection == "selective-input" {
				var config logpolicy.InputConfig
				_ = json.Unmarshal(encoded, &config)
				config.ID = "draft-preview"
				policies, err = logpolicy.Compile([]logpolicy.InputConfig{config}, nil)
			} else {
				var config logpolicy.OutputConfig
				_ = json.Unmarshal(encoded, &config)
				config.ID = "draft-preview"
				policies, err = logpolicy.Compile(nil, []logpolicy.OutputConfig{config})
			}
		}
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	matched, excluded := []string{}, []string{}
	results := []map[string]any{}
	before, after := []map[string]any{}, []map[string]any{}
	removedSet := map[string]bool{}
	parsed, failed := 0, 0
	for _, raw := range rows {
		if err := r.Context().Err(); err != nil {
			jsonError(w, "policy preview cancelled", http.StatusRequestTimeout)
			return
		}
		decision := policies.MatchInput(raw, input.Service, "")
		if !decision.Allowed {
			excluded = append(excluded, raw)
			continue
		}
		matched = append(matched, raw)
		if path == "input/preview" && !input.Parse {
			continue
		}
		result := s.runAssuranceContext(r.Context(), assuranceRequest{Raw: raw, Service: input.Service, ParserID: input.ParserID, PreserveSource: true, BypassLogPolicies: true})
		original, _ := result["actual"].(map[string]any)
		if original == nil {
			original = map[string]any{}
		}
		filtered := policies.FilterFields(original)
		for key := range original {
			if _, exists := filtered[key]; !exists {
				removedSet[key] = true
			}
		}
		before = append(before, original)
		after = append(after, filtered)
		passed := result["passed"] == true
		if passed {
			parsed++
		} else {
			failed++
		}
		results = append(results, map[string]any{"raw": raw, "passed": passed, "actual": filtered, "before": original, "after": filtered, "errors": result["errors"], "route": result["route"], "parser": result["parser"], "policy_decision": decision})
	}
	removed := make([]string, 0, len(removedSet))
	for key := range removedSet {
		removed = append(removed, key)
	}
	sort.Strings(removed)
	jsonOK(w, map[string]any{"scope": scope, "bundle_hash": bundleHash, "total": len(rows), "accepted_count": len(matched), "excluded_count": len(excluded), "matched_raw": matched, "excluded_raw": excluded, "parse_requested": path == "output/preview" || input.Parse, "results": results, "before": before, "after": after, "removed_fields": removed, "parsed_count": parsed, "failed_count": failed, "persisted": false, "input_enabled": policies.InputEnabled(), "output_enabled": policies.OutputEnabled(), "framing": "raw text uses physical lines; records[] accepts already framed multiline records"})
}

func removedLogPolicyFields(before, after map[string]any) []string {
	removed := []string{}
	for key := range before {
		if _, ok := after[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(removed)
	return removed
}

func (s *Server) controllerLogPolicies(ctx context.Context, snapshot *automaticRuntimeSnapshot) (*logpolicy.Set, error) {
	if snapshot != nil && snapshot.parser != nil {
		return snapshot.parser.PolicySnapshot(), nil
	}
	return s.persistedLogPolicies()
}

func policyAssuranceSkipped(request assuranceRequest, route, message string) map[string]any {
	errors := []string{}
	if message != "" {
		errors = append(errors, message)
	}
	return map[string]any{"raw": request.Raw, "raw_sha256": fmt.Sprintf("%x", hashBytes([]byte(request.Raw))), "actual": map[string]any{}, "desired": request.Desired, "diff": []any{}, "passed": false, "filtered_out": route == "filtered_out", "parse_attempted": false, "route": route, "errors": errors, "score": 0, "latency_us": 0, "retained": false, "counts": map[string]int{"attempts": 0, "fallbacks": 0, "actual": 0, "desired": len(request.Desired), "matches": 0, "differences": 0}, "trace": []map[string]any{{"stage": "selective_input", "outcome": route, "success": route == "filtered_out"}}, "parser": map[string]any{"name": "not_attempted", "version": 0, "confidence": 0, "strategy": "input_policy"}, "coverage": map[string]any{"expected": len(request.Desired), "found": 0, "percent": 0, "missing": []string{}}, "comparison_enabled": len(request.Desired) > 0, "evidence_spans": []any{}, "parser_creation_helper": map[string]any{"parsed_json": map[string]any{}, "fields": []any{}, "requires_human_approval": true, "blocked_by_input_policy": true}}
}

func (s *Server) queueNewPolicyCapableClient(ctx context.Context, nodeID string) {
	bundle, err := s.buildActiveParserBundle(ctx)
	if err == nil && bundleRequiresLogPolicies(bundle) {
		s.queueEnrollmentParserSync(ctx, nodeID)
	}
}
