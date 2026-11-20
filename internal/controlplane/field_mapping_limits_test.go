package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFieldSenseAdmissionIsolationAndRecovery(t *testing.T) {
	s := &Server{cfg: Config{FieldSenseAnalysisConcurrency: 1, FieldSenseAnalysisTimeoutMS: 50}}
	ctx, done, ok := s.beginFieldSenseAnalysis(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	if !ok {
		t.Fatal("first analysis rejected")
	}
	busy := httptest.NewRecorder()
	s.handleMappingPreview(busy, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if busy.Code != http.StatusTooManyRequests || busy.Header().Get("Retry-After") != "1" {
		t.Fatalf("busy analysis: %d", busy.Code)
	}
	kvBusy := httptest.NewRecorder()
	s.handleKVInspect(kvBusy, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if kvBusy.Code != http.StatusTooManyRequests || kvBusy.Header().Get("Retry-After") != "1" {
		t.Fatalf("KV inspection bypassed shared admission: %d", kvBusy.Code)
	}
	// A deadline frees capacity when the handler exits; no background queue starts.
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("analysis deadline missing")
	}
	done()
	malformed := httptest.NewRecorder()
	s.handleMappingPreview(malformed, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if malformed.Code != http.StatusBadRequest || len(s.fieldSenseAnalysis().slots) != 0 {
		t.Fatal("invalid input leaked an analysis slot")
	}
	valid := httptest.NewRecorder()
	s.handleMappingPreview(valid, httptest.NewRequest("POST", "/", strings.NewReader(`{"raw":"hello","plan":{"version":1,"fields":[{"name":"message","type":"string","method":"position","source":"1"}]}}`)))
	if valid.Code != 200 || !strings.Contains(valid.Body.String(), `"passed":true`) || !strings.Contains(valid.Body.String(), `"trace"`) {
		t.Fatalf("capacity did not recover: %s", valid.Body.String())
	}
	if s.fieldSenseAnalysis().timedOut.Load() != 1 {
		t.Fatal("deadline metric missing")
	}
}

func TestFieldSenseCanceledRequestCannotOccupyCapacity(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	_, _, ok := s.beginFieldSenseAnalysis(w, r)
	if ok || w.Code != http.StatusRequestTimeout || len(s.fieldSenseAnalysis().slots) != 0 {
		t.Fatal("canceled request admitted")
	}
}

func TestFieldSenseWorkflowBudgetKeepsStandardExtractionDeadline(t *testing.T) {
	s := &Server{cfg: Config{FieldSenseAnalysisConcurrency: 1, FieldSenseAnalysisTimeoutMS: 50}}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	workflow, done, ok := s.beginFieldSenseAnalysisBudget(httptest.NewRecorder(), request, metadataViewReadBudget+s.fieldSenseAnalysis().timeout)
	if !ok {
		t.Fatal("workflow admission failed")
	}
	deadline, _ := workflow.Deadline()
	if time.Until(deadline) <= metadataViewReadBudget {
		t.Fatal("workflow did not reserve separate metadata and extraction phases")
	}
	busy := httptest.NewRecorder()
	if _, _, ok := s.beginFieldSenseAnalysis(busy, request); ok || busy.Code != 429 {
		t.Fatal("workflow bypassed shared capacity")
	}
	done()
	extraction, finish, ok := s.beginFieldSenseAnalysis(httptest.NewRecorder(), request)
	if !ok {
		t.Fatal("workflow leaked its slot")
	}
	defer finish()
	deadline, _ = extraction.Deadline()
	if time.Until(deadline) > 50*time.Millisecond {
		t.Fatal("ordinary extraction inherited the longer metadata budget")
	}
	select {
	case <-extraction.Done():
	case <-time.After(time.Second):
		t.Fatal("ordinary extraction deadline missing")
	}
	w := httptest.NewRecorder()
	if !fieldSenseContextError(w, extraction) || w.Code != 408 {
		t.Fatal("ordinary extraction timeout changed")
	}
}
