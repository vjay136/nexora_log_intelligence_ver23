package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"time"

	"nexora.local/nli-v20/internal/familyprofile"
	"nexora.local/nli-v20/internal/fieldmapping"
	"nexora.local/nli-v20/internal/middleware"
	"nexora.local/nli-v20/internal/registry"
	metastore "nexora.local/nli-v20/internal/store"
)

const (
	napiMaxSamples     = 50
	napiMaxTotalBytes  = 2 << 20
	napiMaxCandidates  = 8
	napiMaxRegexBytes  = 4096
	napiMaxRegexInst   = 4096
	napiMaxCaptureSets = 64
	napiGenerator      = "napi-bounded-v1"
	napiExamplesNeeded = "Open Complete validation examples in Parser Creation Workspace and add representative redacted validation examples with exact expected JSON. Save the draft, then submit it for review."
)

type napiSynthesisInput struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	Version              string             `json:"version"`
	Discovery            []assuranceRequest `json:"discovery"`
	HeldOut              []assuranceRequest `json:"held_out"`
	Negative             []string           `json:"negative,omitempty"`
	CandidateLimit       int                `json:"candidate_limit,omitempty"`
	RetainReviewExamples bool               `json:"retain_review_examples,omitempty"`
}

type napiRegexSafety struct {
	Safe               bool     `json:"safe"`
	Engine             string   `json:"engine"`
	PatternBytes       int      `json:"pattern_bytes"`
	CaptureGroups      int      `json:"capture_groups"`
	Instructions       int      `json:"instructions"`
	Anchored           bool     `json:"anchored"`
	PredictableRuntime bool     `json:"predictable_runtime"`
	Warnings           []string `json:"warnings"`
	Errors             []string `json:"errors"`
}

type napiCandidate struct {
	ID           string
	Strategy     string
	Rationale    []string
	Definition   map[string]any
	Safety       napiRegexSafety
	Evaluation   map[string]any
	Eligible     bool
	RuntimeReady bool
}

// handleNAPISynthesize runs bounded, deterministic discovery outside the
// ingestion hot path. It persists only the selected declarative draft and
// hashes/evidence. Supplied records are copied into review cases only when the
// operator explicitly authorizes retention of their redacted examples.
func (s *Server) handleNAPISynthesize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	principal := s.authorize(w, r, middleware.PermissionManageParsers)
	if principal == nil {
		return
	}
	var input napiSynthesisInput
	if decodeJSON(r, &input, napiMaxTotalBytes+(256<<10)) != nil {
		jsonError(w, "invalid synthesis request", http.StatusBadRequest)
		return
	}
	if input.Version == "" {
		input.Version = "0.1.0"
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 128 || !semverPattern.MatchString(input.Version) {
		jsonError(w, "name and semantic version are required", http.StatusBadRequest)
		return
	}
	if len(input.Discovery) < 2 || len(input.Discovery) > napiMaxSamples || len(input.HeldOut) < 1 || len(input.HeldOut) > napiMaxSamples || len(input.Negative) > napiMaxSamples {
		jsonError(w, "2..50 discovery, 1..50 held-out and at most 50 negative samples are required", http.StatusBadRequest)
		return
	}
	if input.CandidateLimit == 0 {
		input.CandidateLimit = napiMaxCandidates
	}
	if input.CandidateLimit < 1 || input.CandidateLimit > napiMaxCandidates {
		jsonError(w, "candidate_limit must be 1..8", http.StatusBadRequest)
		return
	}
	if err := normalizeNAPISamples(&input); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if napiSamplesOverlap(input.Discovery, input.HeldOut) {
		jsonError(w, "discovery and held-out datasets must not contain the same normalized record", http.StatusBadRequest)
		return
	}
	id := safeID(input.ID)
	if id == "" {
		id = safeID(input.Name)
	}
	if len(id) < 2 || len(id) > 56 {
		jsonError(w, "parser id must contain 2..56 supported characters", http.StatusBadRequest)
		return
	}
	if familyprofile.IsBuiltinPackID(id) || id == "deleted" {
		jsonError(w, "parser id is reserved or belongs to the embedded baseline", http.StatusConflict)
		return
	}

	started := time.Now()
	candidates := s.generateNAPICandidates(id, input.Discovery, input.CandidateLimit)
	for index := range candidates {
		candidates[index].Safety = analyzeNAPIRegex(candidates[index].Definition)
		candidates[index].Evaluation = evaluateNAPICandidate(candidates[index].Definition, input.Discovery, input.HeldOut, input.Negative)
		if candidates[index].Safety.Safe && napiEvaluationEligible(candidates[index].Evaluation) {
			candidates[index].RuntimeReady = validateNAPIRuntime(r.Context(), id, input.Version, principal.Username, candidates[index].Definition, append(append([]assuranceRequest(nil), input.Discovery...), input.HeldOut...)) == nil
		}
		candidates[index].Eligible = candidates[index].RuntimeReady
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Eligible != candidates[j].Eligible {
			return candidates[i].Eligible
		}
		left, _ := candidates[i].Evaluation["score"].(int)
		right, _ := candidates[j].Evaluation["score"].(int)
		if left != right {
			return left > right
		}
		if candidates[i].Safety.Instructions != candidates[j].Safety.Instructions {
			return candidates[i].Safety.Instructions < candidates[j].Safety.Instructions
		}
		return candidates[i].ID < candidates[j].ID
	})

	reports := napiCandidateReports(candidates)
	if len(candidates) == 0 || !candidates[0].Eligible {
		s.auditAction(principal, "napi.synthesize", "parser-packs/"+id, "failure", map[string]string{"reason": "no_eligible_candidate"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "rejected", "draft_created": false, "reason": "no candidate passed discovery, independent held-out, negative, safety and production runtime gates", "candidates": reports})
		return
	}

	selected := candidates[0]
	provenance := map[string]any{
		"engine":                  napiGenerator,
		"generated_at":            time.Now().UTC(),
		"discovery_sample_hashes": napiSampleHashes(input.Discovery),
		"held_out_sample_hashes":  napiSampleHashes(input.HeldOut),
		"negative_sample_hashes":  napiRawHashes(input.Negative),
		"discovery_count":         len(input.Discovery),
		"held_out_count":          len(input.HeldOut),
		"negative_count":          len(input.Negative),
		"separation_enforced":     true,
		"raw_samples_persisted":   false,
	}
	validation := selected.Evaluation
	reviewValidation := map[string]any{"status": "requires_validation_examples", "reason": napiExamplesNeeded}
	var reviewCases []assuranceRequest
	if input.RetainReviewExamples {
		// The operator explicitly authorizes retaining the supplied redacted
		// expected-output examples. Re-run the exact persisted artifact through
		// production validation; synthesis scores are not review evidence.
		reviewCases = append(append([]assuranceRequest(nil), input.Discovery...), input.HeldOut...)
		reviewValidation = validateNAPIReviewDraft(r.Context(), id, input.Version, principal.Username, selected.Definition, reviewCases)
	}
	needsExamples := len(reviewCases) == 0
	nextAction := napiExamplesNeeded
	if !needsExamples {
		nextAction = "Open the saved draft in Parser Creation Workspace, inspect the saved exact validation results, then submit for independent review. Publication and fleet rollout require approval."
	}
	provenance["raw_samples_persisted"] = input.RetainReviewExamples
	provenance["review_examples_retention_authorized"] = input.RetainReviewExamples
	checksum := parserArtifactChecksum(selected.Definition)
	payload, _ := json.Marshal(map[string]any{
		"id": id, "name": input.Name, "version": input.Version,
		"parser": selected.Definition, "artifact_checksum": checksum,
		"validation": reviewValidation, "validation_passed": reviewValidation["status"] == "passed", "cases": reviewCases,
		"synthesis_evidence": map[string]any{
			"selected_candidate": selected.ID, "strategy": selected.Strategy,
			"rationale": selected.Rationale, "regex_safety": selected.Safety,
			"evaluation": validation, "candidate_reports": reports,
			"provenance":  provenance,
			"limitations": []string{"validated only for the supplied bounded samples", "production activation still requires independent review and publish", "no claim is made for unseen log formats"},
		},
		"review_state": "draft", "activated": false,
		"requires_human_approval": true, "requires_validation_examples": needsExamples, "generated_by": napiGenerator,
	})
	saved, ok := s.saveNAPIDraft(w, r, principal.Username, id, payload)
	if !ok {
		return
	}
	nupireRecord, nupireErr := s.registerNAPICandidate(r.Context(), id, input.Version, principal.Username, selected, input.Discovery, input.HeldOut)
	if nupireErr != nil {
		s.auditAction(principal, "nupire.napi.bind", "parser-packs/"+id, "failure", map[string]string{"reason": nupireErr.Error()})
		nupireRecord = map[string]any{"state": "unavailable", "reason": nupireErr.Error()}
	} else {
		s.auditAction(principal, "nupire.napi.bind", "parser-packs/"+id, "success", map[string]string{"candidate_id": fmt.Sprint(nupireRecord["id"]), "state": fmt.Sprint(nupireRecord["state"])})
	}
	nupireRecord["parser_id"] = id
	nupireRecord["scope"] = "evaluation"
	s.auditAction(principal, "napi.synthesize", "parser-packs/"+id, "success", map[string]string{"state": "draft", "strategy": selected.Strategy, "held_out": fmt.Sprint(len(input.HeldOut))})
	jsonCreated(w, map[string]any{
		"id": id, "revision": saved.Revision, "state": "draft", "draft_created": true,
		"selected_candidate": selected.ID, "strategy": selected.Strategy,
		"validation": validation, "regex_safety": selected.Safety,
		"candidates": reports, "provenance": provenance,
		"nupire":                  nupireRecord,
		"requires_human_approval": true, "requires_validation_examples": needsExamples, "next_action": nextAction,
		"review_validation": reviewValidation, "review_examples_retained": len(reviewCases),
		"artifact_checksum": checksum, "published": false,
		"elapsed_us": time.Since(started).Microseconds(),
	})
}

func (s *Server) saveNAPIDraft(w http.ResponseWriter, r *http.Request, author, id string, payload []byte) (metastore.Document, bool) {
	s.parserMutationMu.Lock()
	defer s.parserMutationMu.Unlock()
	ctx := r.Context()
	existing, err := s.metadata.Get(ctx, "parser-packs", id, 0)
	if err == nil {
		if existing.State != "draft" && existing.State != "rejected" {
			jsonError(w, "an in-review, approved or published parser with this id cannot be replaced by synthesis", http.StatusConflict)
			return metastore.Document{}, false
		}
		author = existing.CreatedBy
	} else if !errors.Is(err, os.ErrNotExist) {
		jsonError(w, "the current parser revision could not be verified", http.StatusServiceUnavailable)
		return metastore.Document{}, false
	}
	saved, err := s.metadata.Put(ctx, metastore.Document{Collection: "parser-packs", ID: id, State: "draft", Payload: payload, CreatedBy: author})
	if err != nil {
		jsonError(w, "NAPI draft persistence failed", http.StatusServiceUnavailable)
		return metastore.Document{}, false
	}
	return saved, true
}

func validateNAPIRuntime(ctx context.Context, id, version, author string, definition map[string]any, cases []assuranceRequest) error {
	pack, err := assuranceRuntimePack(id, version, author, definition, cases)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(pack)
	if err != nil {
		return err
	}
	_, err = familyprofile.ValidateManagedPackBytesContext(ctx, id, encoded)
	return err
}

func isNAPIReviewDraft(body map[string]any) bool {
	if body["generated_by"] == napiGenerator {
		return true
	}
	recovery, _ := body["recovery"].(map[string]any)
	filename, _ := recovery["source_filename"].(string)
	return recovery["source_format"] == "user-export" && strings.HasPrefix(strings.ToLower(filename), "napi-")
}

// Older NAPI exports carry registry-only KV or JSON selectors. The conversion
// is run only when an operator edits a draft with real validation examples.
// It does not invent missing selectors, sample input, or expected output.
func upgradeLegacyNAPIReviewDefinition(definition map[string]any) error {
	patternType, _ := definition["pattern_type"].(string)
	format, _ := definition["format"].(string)
	if patternType != "" || (format != "json" && format != "key_value") {
		return nil
	}
	var fields []registry.FieldDef
	encoded, err := json.Marshal(definition["fields"])
	if err != nil || json.Unmarshal(encoded, &fields) != nil || len(fields) == 0 {
		return errors.New("legacy NAPI definition needs explicit source selectors or a new synthesized draft")
	}
	plan, err := napiMappingPlan(format, fields)
	if err != nil {
		return fmt.Errorf("legacy NAPI definition needs supported source selectors or a new synthesis: %w", err)
	}
	definition["pattern_type"] = "mapping"
	definition["mapping_plan"] = plan
	delete(definition, "pattern")
	delete(definition, "fields")
	return nil
}

func validateNAPIReviewDraft(ctx context.Context, id, version, author string, definition map[string]any, cases []assuranceRequest) map[string]any {
	validation := validateParserCandidateContext(ctx, definition, cases)
	if validation["status"] == "passed" {
		if err := validateNAPIRuntime(ctx, id, version, author, definition, cases); err != nil {
			validation["status"] = "runtime_incompatible"
			validation["reason"] = err.Error()
		}
	}
	return validation
}

func normalizeNAPISamples(input *napiSynthesisInput) error {
	total := 0
	normalize := func(items []assuranceRequest) error {
		for i := range items {
			items[i].Raw = normalizeAssuranceRaw(items[i].Raw)
			total += len(items[i].Raw)
			if items[i].Raw == "" || len(items[i].Raw) > 1<<20 || len(items[i].Desired) == 0 || len(items[i].Desired) > 256 {
				return fmt.Errorf("every synthesis sample requires bounded raw input and 1..256 expected fields")
			}
		}
		return nil
	}
	if err := normalize(input.Discovery); err != nil {
		return err
	}
	if err := normalize(input.HeldOut); err != nil {
		return err
	}
	for i := range input.Negative {
		input.Negative[i] = normalizeAssuranceRaw(input.Negative[i])
		total += len(input.Negative[i])
		if input.Negative[i] == "" || len(input.Negative[i]) > 1<<20 {
			return fmt.Errorf("negative samples must be bounded and non-empty")
		}
	}
	if total > napiMaxTotalBytes {
		return fmt.Errorf("combined synthesis samples exceed 2 MiB")
	}
	return nil
}

func napiSamplesOverlap(discovery, heldOut []assuranceRequest) bool {
	seen := make(map[string]struct{}, len(discovery))
	for _, sample := range discovery {
		seen[hex.EncodeToString(hashBytes([]byte(sample.Raw)))] = struct{}{}
	}
	for _, sample := range heldOut {
		if _, exists := seen[hex.EncodeToString(hashBytes([]byte(sample.Raw)))]; exists {
			return true
		}
	}
	return false
}

func (s *Server) generateNAPICandidates(id string, discovery []assuranceRequest, limit int) []napiCandidate {
	fields := inferNAPIFields(discovery)
	out := make([]napiCandidate, 0, limit)
	add := func(candidate napiCandidate) {
		if len(out) >= limit || candidate.Definition == nil {
			return
		}
		if unsafeDeclarative(candidate.Definition) == nil {
			out = append(out, candidate)
		}
	}
	if definition := synthesizeNAPIMailMapping(id, discovery); definition != nil {
		add(napiCandidate{ID: "mail-header-kv", Strategy: "header_kv", Rationale: []string{"reuses the production named mail-header template and complete global KV tail mapping", "header components are bounded captures rather than guessed occurrences of expected values", "discovery and independent held-out exact outputs and negative records still gate persistence"}, Definition: definition})
	}
	if allNAPIJSON(discovery) {
		add(napiCandidate{ID: "json-fields", Strategy: "json", Rationale: []string{"every discovery record is a JSON object", "field sources use the same native mapping stage as production"}, Definition: napiMappingDefinition(id, "json", fields)})
	}
	add(napiCandidate{ID: "key-value", Strategy: "key_value", Rationale: []string{"uses the existing production key-value mapping", "field sources are derived from expected keys"}, Definition: napiMappingDefinition(id, "key_value", fields)})
	if definition, rationale := synthesizeNAPIRegex(id, discovery, fields); definition != nil {
		add(napiCandidate{ID: "anchored-regex", Strategy: "regex", Rationale: rationale, Definition: definition})
	}
	if s.assuranceDeps != nil && s.assuranceDeps.Registry != nil {
		registered := s.assuranceDeps.Registry.All()
		sort.Slice(registered, func(i, j int) bool { return registered[i].ID < registered[j].ID })
		for _, parser := range registered {
			encoded, _ := json.Marshal(parser)
			var definition map[string]any
			if json.Unmarshal(encoded, &definition) == nil {
				// A synthesized parser is a new review object. Reuse the approved
				// primitive, but bind the candidate to the requested draft identity.
				definition["id"] = id
				definition["version"] = 1
				delete(definition, "tests")
				add(napiCandidate{ID: "registered-" + parser.ID, Strategy: "registered", Rationale: []string{"reuses an existing reviewed runtime parser primitive", "candidate is still re-evaluated against discovery and held-out samples"}, Definition: definition})
			}
		}
	}
	return out
}

// Recognized numeric-prefix mail records use the same bounded header template
// and KV composition as authored production templates. In particular a small
// field such as minor_pid=0 must not be located by counting the character '0'
// throughout timestamps and IDs. Unsupported layouts retain the existing
// candidate gates; no broad catch-all header or unparsed tail is introduced.
func synthesizeNAPIMailMapping(id string, samples []assuranceRequest) map[string]any {
	if len(samples) == 0 {
		return nil
	}
	raw := make([]string, 0, len(samples))
	for _, sample := range samples {
		if !fieldmapping.HasMailHeaderExtension(sample.Raw) || !aiMailHeader.MatchString(sample.Raw) {
			return nil
		}
		raw = append(raw, sample.Raw)
	}
	pattern, optional := mailTemplatePattern(raw...)
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	header := fieldmapping.HeaderTemplate{Engine: "re2", Pattern: pattern, Fields: map[string]string{}}
	for _, name := range compiled.SubexpNames()[1:] {
		if name == "" {
			return nil
		}
		header.Fields[name] = name
	}
	for _, name := range optional {
		value, ok := name.(string)
		if !ok {
			return nil
		}
		header.OptionalFields = append(header.OptionalFields, value)
	}
	plan, err := fieldmapping.ComposeTemplates(header, nil)
	if err != nil {
		return nil
	}
	if _, err = fieldmapping.Compile(plan); err != nil {
		return nil
	}
	return map[string]any{"id": id, "version": 1, "description": "NAPI bounded complete mail-header and KV candidate", "format": "smtp_native", "pattern_type": "mapping", "mapping_plan": plan}
}

func inferNAPIFields(samples []assuranceRequest) []registry.FieldDef {
	keys := map[string]bool{}
	for _, sample := range samples {
		for key := range sample.Desired {
			if knownCatalogKeyPattern.MatchString(key) {
				keys[key] = true
			}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	fields := make([]registry.FieldDef, 0, len(ordered))
	for _, key := range ordered {
		kind, present := "", 0
		for _, sample := range samples {
			if value, ok := sample.Desired[key]; ok {
				present++
				current := napiFieldType(value)
				if kind == "" {
					kind = current
				} else if kind != current {
					kind = "string"
				}
			}
		}
		fields = append(fields, registry.FieldDef{Name: key, Type: kind, Required: present == len(samples)})
	}
	return fields
}

func napiFieldType(value any) string {
	switch value.(type) {
	case bool:
		return "boolean"
	case float32, float64:
		if number, ok := value.(float64); ok && math.Trunc(number) == number {
			return "integer"
		}
		return "float"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer"
	default:
		return "string"
	}
}

func napiParserDefinition(id, format, pattern, patternType string, fields []registry.FieldDef, sourceKind string) map[string]any {
	definitions := make([]any, 0, len(fields))
	for _, field := range fields {
		source := sourceKind + ":" + field.Name
		if sourceKind == "group" {
			source = "group:" + field.Name
		}
		definitions = append(definitions, map[string]any{"name": field.Name, "source": source, "type": field.Type, "required": field.Required})
	}
	return map[string]any{"id": id, "version": 1, "description": "NAPI bounded candidate", "format": format, "pattern": pattern, "pattern_type": patternType, "fields": definitions}
}

func napiMappingDefinition(id, format string, fields []registry.FieldDef) map[string]any {
	sourceKind := "kv"
	if format == "json" {
		sourceKind = "json"
	}
	selectors := make([]registry.FieldDef, 0, len(fields))
	for _, field := range fields {
		field.Source = sourceKind + ":" + field.Name
		selectors = append(selectors, field)
	}
	plan, err := napiMappingPlan(format, selectors)
	if err != nil {
		return nil
	}
	return map[string]any{"id": id, "version": 1, "description": "NAPI bounded candidate", "format": format, "pattern_type": "mapping", "mapping_plan": plan}
}

// Both NAPI JSON and KV share the compiled mapping used by Assurance previews
// and the deployed ParserPack runtime. No separate production parser is added.
func napiMappingPlan(format string, fields []registry.FieldDef) (fieldmapping.Plan, error) {
	plan := fieldmapping.Plan{Version: 1, Fields: make([]fieldmapping.Field, 0, len(fields))}
	sourceKind, method := "kv", "key_value"
	if format == "json" {
		sourceKind, method = "json", "json_path"
	}
	for _, source := range fields {
		key, ok := strings.CutPrefix(source.Source, sourceKind+":")
		if !ok || key == "" || key == "*" {
			return plan, fmt.Errorf("field %q requires an explicit %s source", source.Name, sourceKind)
		}
		if format == "json" {
			key = "$[" + strconv.Quote(key) + "]"
		}
		policy := "optional"
		if source.Required {
			policy = "required"
		}
		plan.Fields = append(plan.Fields, fieldmapping.Field{Name: source.Name, Method: method, Source: key, Type: source.Type, Policy: policy})
	}
	_, err := fieldmapping.Compile(plan)
	return plan, err
}

func allNAPIJSON(samples []assuranceRequest) bool {
	for _, sample := range samples {
		var value map[string]any
		if json.Unmarshal([]byte(sample.Raw), &value) != nil || value == nil {
			return false
		}
	}
	return true
}

type napiSpan struct {
	name, text, kind string
	start, end       int
}

func synthesizeNAPIRegex(id string, samples []assuranceRequest, fields []registry.FieldDef) (map[string]any, []string) {
	if len(samples) == 0 || len(fields) == 0 {
		return nil, nil
	}
	raw := samples[0].Raw
	spans := make([]napiSpan, 0, len(fields))
	for _, field := range fields {
		value, ok := samples[0].Desired[field.Name]
		if !ok {
			continue
		}
		text := fmt.Sprint(value)
		if text == "" || strings.Count(raw, text) != 1 {
			return nil, nil
		}
		start := strings.Index(raw, text)
		spans = append(spans, napiSpan{name: field.Name, text: text, kind: field.Type, start: start, end: start + len(text)})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for index := 1; index < len(spans); index++ {
		if spans[index].start < spans[index-1].end {
			return nil, nil
		}
	}
	var pattern strings.Builder
	pattern.WriteByte('^')
	position := 0
	for _, span := range spans {
		pattern.WriteString(regexp.QuoteMeta(raw[position:span.start]))
		pattern.WriteString("(?P<" + span.name + ">" + napiCapturePattern(span.kind, span.text) + ")")
		position = span.end
	}
	pattern.WriteString(regexp.QuoteMeta(raw[position:]))
	pattern.WriteByte('$')
	return napiParserDefinition(id, "inferred", pattern.String(), "regex", fields, "group"), []string{"stable literals come from the first discovery shape", "all values are replaced by named typed captures", "anchoring prevents partial-record matches", "all discovery and independent held-out samples must pass before persistence"}
}

func napiCapturePattern(kind, example string) string {
	switch kind {
	case "integer":
		return `[-+]?[0-9]+`
	case "float":
		return `[-+]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)`
	case "boolean":
		return `(?i:true|false|yes|no|on|off)`
	default:
		if strings.ContainsAny(example, " \t") {
			return `.+?`
		}
		return `[^[:space:]]+?`
	}
}

func analyzeNAPIRegex(definition map[string]any) napiRegexSafety {
	pattern, _ := definition["pattern"].(string)
	patternType, _ := definition["pattern_type"].(string)
	report := napiRegexSafety{Safe: true, Engine: "go-re2", PatternBytes: len(pattern), PredictableRuntime: true, Warnings: []string{}, Errors: []string{}}
	if pattern == "" || patternType != "regex" {
		report.Engine = "declarative-non-regex"
		report.Anchored = true
		return report
	}
	report.Anchored = strings.HasPrefix(pattern, "^") && strings.HasSuffix(pattern, "$")
	if len(pattern) > napiMaxRegexBytes {
		report.Errors = append(report.Errors, "pattern exceeds 4096 bytes")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		report.Errors = append(report.Errors, "pattern is not RE2-compatible: "+err.Error())
	} else {
		report.CaptureGroups = compiled.NumSubexp()
		if report.CaptureGroups > napiMaxCaptureSets {
			report.Errors = append(report.Errors, "pattern exceeds 64 capture groups")
		}
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		report.Errors = append(report.Errors, "pattern syntax analysis failed: "+err.Error())
	} else {
		program, compileErr := syntax.Compile(parsed.Simplify())
		if compileErr != nil {
			report.Errors = append(report.Errors, "pattern program could not be compiled")
		} else {
			report.Instructions = len(program.Inst)
			if report.Instructions > napiMaxRegexInst {
				report.Errors = append(report.Errors, "pattern program exceeds 4096 instructions")
			}
		}
	}
	if !report.Anchored {
		report.Warnings = append(report.Warnings, "pattern is not fully anchored")
	}
	if strings.Contains(pattern, ".*") {
		report.Warnings = append(report.Warnings, "pattern contains a broad wildcard")
	}
	report.Safe = len(report.Errors) == 0
	return report
}

func evaluateNAPICandidate(definition map[string]any, discovery, heldOut []assuranceRequest, negative []string) map[string]any {
	encoded, _ := json.Marshal(definition)
	var parser registry.ParserDef
	if json.Unmarshal(encoded, &parser) != nil || registry.Validate(&parser) != nil {
		return map[string]any{"score": 0, "eligible": false, "compile_ok": false, "errors": []string{"candidate failed declarative compilation"}}
	}
	type result struct {
		total, exact, desiredFields, matchedFields, extraFields int
		elapsed                                                 time.Duration
	}
	run := func(samples []assuranceRequest) result {
		value := result{total: len(samples)}
		for _, sample := range samples {
			started := time.Now()
			actual, failures := registry.Apply(&parser, sample.Raw)
			value.elapsed += time.Since(started)
			diff, matches := structuralDiff(actual, sample.Desired)
			value.desiredFields += len(sample.Desired)
			value.matchedFields += matches
			for _, item := range diff {
				if item["status"] == "extra" {
					value.extraFields++
				}
			}
			if len(failures) == 0 && len(diff) == 0 && len(sample.Desired) > 0 {
				value.exact++
			}
		}
		return value
	}
	training := run(discovery)
	testing := run(heldOut)
	falsePositives := 0
	negativeElapsed := time.Duration(0)
	for _, raw := range negative {
		started := time.Now()
		actual, failures := registry.Apply(&parser, raw)
		negativeElapsed += time.Since(started)
		if len(failures) == 0 && len(actual) > 0 {
			falsePositives++
		}
	}
	fieldRecall := func(v result) float64 {
		if v.desiredFields == 0 {
			return 0
		}
		return float64(v.matchedFields) / float64(v.desiredFields)
	}
	fieldPrecision := func(v result) float64 {
		denominator := v.matchedFields + v.extraFields
		if denominator == 0 {
			return 0
		}
		return float64(v.matchedFields) / float64(denominator)
	}
	eligible := training.exact == training.total && testing.exact == testing.total && falsePositives == 0
	score := int(math.Round((fieldRecall(testing)*0.35 + fieldPrecision(testing)*0.25 + float64(testing.exact)/float64(testing.total)*0.30 + func() float64 {
		if falsePositives == 0 {
			return 0.10
		}
		return 0
	}()) * 100))
	return map[string]any{
		"score": score, "eligible": eligible, "compile_ok": true,
		"training":              map[string]any{"total": training.total, "exact": training.exact, "failed": training.total - training.exact, "field_precision": fieldPrecision(training), "field_recall": fieldRecall(training), "elapsed_us": training.elapsed.Microseconds()},
		"held_out":              map[string]any{"total": testing.total, "exact": testing.exact, "failed": testing.total - testing.exact, "field_precision": fieldPrecision(testing), "field_recall": fieldRecall(testing), "elapsed_us": testing.elapsed.Microseconds()},
		"negative":              map[string]any{"total": len(negative), "false_positives": falsePositives, "elapsed_us": negativeElapsed.Microseconds()},
		"exact_output_required": true,
	}
}

func napiEvaluationEligible(evaluation map[string]any) bool {
	eligible, _ := evaluation["eligible"].(bool)
	return eligible
}

func napiCandidateReports(candidates []napiCandidate) []map[string]any {
	out := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, map[string]any{"id": candidate.ID, "strategy": candidate.Strategy, "rationale": candidate.Rationale, "definition": candidate.Definition, "regex_safety": candidate.Safety, "evaluation": candidate.Evaluation, "eligible": candidate.Eligible, "runtime_ready": candidate.RuntimeReady})
	}
	return out
}

func napiSampleHashes(samples []assuranceRequest) []map[string]any {
	out := make([]map[string]any, 0, len(samples))
	for _, sample := range samples {
		out = append(out, map[string]any{"raw_sha256": hex.EncodeToString(hashBytes([]byte(sample.Raw))), "desired_sha256": napiJSONHash(sample.Desired)})
	}
	return out
}

func napiRawHashes(samples []string) []string {
	out := make([]string, 0, len(samples))
	for _, sample := range samples {
		out = append(out, hex.EncodeToString(hashBytes([]byte(sample))))
	}
	return out
}

func napiJSONHash(value any) string {
	encoded, _ := json.Marshal(value)
	return hex.EncodeToString(hashBytes(encoded))
}
