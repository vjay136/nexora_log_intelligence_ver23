package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"nexora.local/nli-v20/internal/fieldmapping"
	"nexora.local/nli-v20/internal/mixedkv"
)

const (
	maxTemplateComposeSamples = 500
	maxTemplateComposeDetails = 5
)

type templateComposeRef struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}

type templateComposeHeader = fieldmapping.HeaderTemplate

type templateComposeStoreError struct{ cause error }

func (e *templateComposeStoreError) Error() string {
	return "selected template revision could not be loaded from controller metadata"
}
func (e *templateComposeStoreError) Unwrap() error { return e.cause }

func templateComposeLookupError(w http.ResponseWriter, err error) {
	var backend *templateComposeStoreError
	if errors.As(err, &backend) {
		metadataFailure(w, backend.Error(), backend.cause)
		return
	}
	jsonError(w, err.Error(), http.StatusBadRequest)
}

func (s *Server) templateComposeConfig(ctx context.Context, collection string, ref templateComposeRef) (json.RawMessage, error) {
	if ref.Revision < 1 || ref.ID == "" || safeID(ref.ID) != ref.ID {
		return nil, fmt.Errorf("select an exact %s revision", collection)
	}
	doc, err := s.metadata.Get(ctx, collection, ref.ID, ref.Revision)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &templateComposeStoreError{cause: err}
	}
	if err != nil || doc.Deleted || doc.State == "revoked" {
		return nil, fmt.Errorf("selected %s revision is unavailable", collection)
	}
	var payload struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(doc.Payload, &payload); err != nil || len(payload.Config) == 0 {
		return nil, fmt.Errorf("selected %s revision has no configuration", collection)
	}
	return payload.Config, nil
}

func composeTemplateMapping(header templateComposeHeader, kv mixedkv.Config) (fieldmapping.Plan, error) {
	return fieldmapping.ComposeTemplates(header, &kv)
}

func (s *Server) handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	admission := s.fieldSenseAnalysis()
	requestContext, done, ok := s.beginFieldSenseAnalysisBudget(w, r, metadataViewReadBudget+admission.timeout)
	if !ok {
		return
	}
	defer done()
	var input struct {
		Header  templateComposeRef `json:"header"`
		KV      templateComposeRef `json:"kv"`
		Samples []string           `json:"samples"`
	}
	if err := decodeJSON(r, &input, 2<<20); err != nil || len(input.Samples) == 0 || len(input.Samples) > maxTemplateComposeSamples {
		jsonError(w, "send 1 to 500 sample records with an exact header revision and an optional KV template revision, up to 2 MiB total", http.StatusBadRequest)
		return
	}
	metadataContext, cancelMetadata := context.WithTimeout(requestContext, metadataViewReadBudget)
	defer cancelMetadata()
	headerConfig, err := s.templateComposeConfig(metadataContext, "templates", input.Header)
	if err != nil {
		templateComposeLookupError(w, err)
		return
	}
	var kvConfig json.RawMessage
	if input.KV.ID != "" && input.KV.ID != fieldmapping.GlobalKVTemplateID {
		kvConfig, err = s.templateComposeConfig(metadataContext, "kv-config", input.KV)
		if err != nil {
			templateComposeLookupError(w, err)
			return
		}
	} else if input.KV.Revision != 0 {
		jsonError(w, "the built-in Global AutoSense profile has no saved revision", http.StatusBadRequest)
		return
	}
	cancelMetadata()
	ctx, cancelAnalysis := context.WithTimeout(requestContext, admission.timeout)
	defer func() {
		if ctx.Err() == context.DeadlineExceeded && requestContext.Err() == nil {
			admission.timedOut.Add(1)
		}
		cancelAnalysis()
	}()
	var header templateComposeHeader
	if json.Unmarshal(headerConfig, &header) != nil {
		jsonError(w, "invalid header template configuration", http.StatusBadRequest)
		return
	}
	var kv *mixedkv.Config
	if kvConfig != nil {
		decoder := json.NewDecoder(bytes.NewReader(kvConfig))
		decoder.DisallowUnknownFields()
		kv = new(mixedkv.Config)
		if err := decoder.Decode(kv); err != nil {
			jsonError(w, "KV template configuration is invalid or contains unsupported options", http.StatusBadRequest)
			return
		}
	}
	plan, err := fieldmapping.ComposeTemplates(header, kv)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	compiled, err := fieldmapping.Compile(plan)
	if fieldSenseContextError(w, ctx) {
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	examples, failures := []map[string]any{}, []map[string]any{}
	failed := 0
	for i, raw := range input.Samples {
		result, err := compiled.Execute(ctx, raw)
		if fieldSenseContextError(w, ctx) {
			return
		}
		if err == nil {
			err = compiled.ValidateComplete(raw, result)
		}
		if err != nil {
			failed++
			if len(failures) < maxTemplateComposeDetails {
				failures = append(failures, map[string]any{"line": i + 1, "error": err.Error()})
			}
		} else if len(examples) < maxTemplateComposeDetails {
			examples = append(examples, map[string]any{"line": i + 1, "actual": orderedMappingValues(result)})
		}
	}
	jsonOK(w, map[string]any{
		"plan": plan, "scope_pattern": header.Pattern,
		"passed": failed == 0, "total": len(input.Samples), "failed": failed, "examples": examples, "failures": failures,
		"persisted": false, "activated": false,
	})
}
