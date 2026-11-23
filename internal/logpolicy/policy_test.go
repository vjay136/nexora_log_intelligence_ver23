package logpolicy

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var sampleLines = []string{
	"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C4:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
	"20250812 130035121+0100 aaa-gmailrgo009 smtp 3609 0 140293780948736 Note;SmtpServerEHLO(2001/4) id=6864BD5E047384C4:domain=server035.mx.internal:host=11.22.33.44",
	"20250812 130035122+0100 aaa-gmailrgo009 smtp 3609 0 140293768701696 Note;SmtpServerSTARTTLSIn(2001/39) id=6864BD5E047384C3:tls=TLSv1.2:cipher=ECDHE-RSA-AES256-GCM-SHA384",
}

func mustPolicy(t *testing.T, inputs []InputConfig, outputs []OutputConfig) *Set {
	t.Helper()
	p, e := Compile(inputs, outputs)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func include(field, operator string, values ...string) InputConfig {
	return InputConfig{ID: "fixture", Enabled: true, MatchMode: "all", Rules: []Rule{{Field: field, Operator: operator, Values: values}}}
}

func TestProvidedEHLOSelectionIsExactBeforeParsing(t *testing.T) {
	p := mustPolicy(t, []InputConfig{include("event", "equals", "SmtpServerEHLO")}, nil)
	for i, line := range sampleLines {
		if got := p.MatchInput(line, "auto", "local"); got.Allowed != (i == 1) {
			t.Fatalf("sample%d decision%+v", i, got)
		}
	}
	metadata := Metadata(sampleLines[1], "auto", "local")
	if metadata["hostname"] != "aaa-gmailrgo009" || metadata["event_type"] != "Note" || metadata["year"] != "2025" || metadata["event"] != "SmtpServerEHLO" {
		t.Fatalf("header metadata was confused with KVtail host: %v", metadata)
	}
}
func TestRulesCombinationsCaseAndRawMultiline(t *testing.T) {
	config := include("event", "equals", "SmtpServerEHLO", "SmtpServerSTARTTLSIn")
	config.Rules = append(config.Rules, Rule{Field: "hostname", Operator: "prefix", Values: []string{"AAA-GMAIL"}}, Rule{Field: "service", Operator: "equals", Values: []string{"smtp"}}, Rule{Field: "year", Operator: "equals", Values: []string{"2025"}}, Rule{Field: "loglevel", Operator: "equals", Values: []string{"Note"}})
	p := mustPolicy(t, []InputConfig{config}, nil)
	for _, line := range sampleLines {
		if !p.MatchInput(line, "auto", "local").Allowed {
			t.Fatal("expected exact matching metadata")
		}
	}
	config.Rules[1].CaseSensitive = true
	if mustPolicy(t, []InputConfig{config}, nil).MatchInput(sampleLines[0], "auto", "local").Allowed {
		t.Fatal("case-sensitive mismatch admitted")
	}
	config.MatchMode = "any"
	if !mustPolicy(t, []InputConfig{config}, nil).MatchInput(sampleLines[0], "auto", "local").Allowed {
		t.Fatal("OR rules ignored matching event")
	}
	p = mustPolicy(t, []InputConfig{include("keyword", "contains", "needle")}, nil)
	if !p.MatchInput("first line\n  needle continuation", "", "").Allowed {
		t.Fatal("framed continuation omitted")
	}
	if p.MatchInput("unrelated", "", "").Allowed {
		t.Fatal("nonmatching raw record admitted")
	}
}
func TestDisabledPreservesR8AndEvaluationLimitsFailClosedOnlyWhenEnabled(t *testing.T) {
	config := InputConfig{MatchMode: "any"}
	p := mustPolicy(t, []InputConfig{config}, []OutputConfig{{}})
	long := strings.Repeat("x", MaxRawBytes+1)
	if !p.MatchInputRecord(long, "", "", true).Allowed {
		t.Fatal("disabled policy changed R8 admission")
	}
	p = mustPolicy(t, []InputConfig{include("keyword", "contains", "x")}, nil)
	for _, decision := range []Decision{p.MatchInput(long, "", ""), p.MatchInputRecord("x", "", "", true)} {
		if decision.Allowed || !decision.PolicyError {
			t.Fatal("incomplete/oversized input must not leak to parser or quarantine")
		}
	}
}
func TestOutputFieldRemovalClonesAndPreservesExactKeysValuesAndTypes(t *testing.T) {
	p := mustPolicy(t, nil, []OutputConfig{{Enabled: true, Fields: []string{"hostname", "a.b"}}})
	original := map[string]any{"hostname": "node", "a.b": "literal", "a": map[string]any{"b": "nested intact"}, "status": "failed", "count": int64(9007199254740993), "active": false}
	actual := p.FilterFields(original)
	if _, ok := actual["hostname"]; ok {
		t.Fatal("hostname leaked")
	}
	if _, ok := actual["a.b"]; ok {
		t.Fatal("exact dotted key leaked")
	}
	if !reflect.DeepEqual(actual["a"], original["a"]) || actual["count"] != original["count"] || actual["active"] != false || len(original) != 6 {
		t.Fatal("value/type/nested data or original mutated")
	}
	p = mustPolicy(t, nil, []OutputConfig{{Enabled: true, Fields: []string{"status"}}, {Enabled: true, Fields: []string{"count", "active", "hostname", "a", "a.b"}}})
	if len(p.FilterFields(original)) != 0 {
		t.Fatal("union should permit intentional empty object")
	}
}
func TestStructuredJSONMetadataAndBounds(t *testing.T) {
	p := mustPolicy(t, []InputConfig{include("hostname", "equals", "mail01")}, nil)
	if !p.MatchInput(`{"hostname":"mail01","message":"host=other"}`, "", "").Allowed {
		t.Fatal("JSON message confused with routing metadata")
	}
	if _, e := Compile([]InputConfig{{Enabled: true, MatchMode: "any"}}, nil); e == nil {
		t.Fatal("empty active filter accepted")
	}
	if _, e := Compile(nil, []OutputConfig{{Enabled: true}}); e == nil {
		t.Fatal("empty active field removal accepted")
	}
	if _, e := Compile([]InputConfig{include("keyword", "regex", ".*")}, nil); e == nil {
		t.Fatal("unbounded operator accepted")
	}
	if _, e := Compile(nil, []OutputConfig{{Fields: []string{"a", "a"}}}); e == nil {
		t.Fatal("duplicate fields accepted")
	}
}
func TestMillionSelectiveAndOutputPolicies(t *testing.T) {
	if os.Getenv("NLI_POLICY_MILLION") != "1" {
		t.Skip("opt-in million-record stress")
	}
	p := mustPolicy(t, []InputConfig{include("event", "equals", "SmtpServerEHLO")}, []OutputConfig{{Enabled: true, Fields: []string{"id", "hostname"}}})
	start := time.Now()
	admitted, excluded := 0, 0
	for i := 0; i < 1000000; i++ {
		line := sampleLines[i%3]
		decision := p.MatchInput(line, "smtp", "node")
		if !decision.Allowed {
			excluded++
			continue
		}
		admitted++
		actual := p.FilterFields(map[string]any{"id": "same", "hostname": "node", "event": "SmtpServerEHLO", "index": i})
		if len(actual) != 2 || actual["index"] != i || actual["event"] != "SmtpServerEHLO" {
			t.Fatalf("record%d output%v", i, actual)
		}
	}
	if admitted != 333333 || excluded != 666667 {
		t.Fatalf("incorrect admission totals%d/%d", admitted, excluded)
	}
	t.Logf("1000000 records: admitted=%d excluded=%d exactoutputsmatched=%d elapsed=%s", admitted, excluded, admitted, time.Since(start))
}
func BenchmarkPolicySelection(b *testing.B) {
	p, _ := Compile([]InputConfig{include("event", "equals", "SmtpServerEHLO")}, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.MatchInput(sampleLines[i%3], "smtp", "node")
	}
}

func TestMillionOutputPoliciesExactRemovalAndSourceImmutability(t *testing.T) {
	if os.Getenv("NLI_POLICY_MILLION") != "1" {
		t.Skip("opt-in million-record output policy stress")
	}
	policy := mustPolicy(t, nil, []OutputConfig{{Enabled: true, Fields: []string{"id", "hostname", "literal.dot"}}})
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		source := map[string]any{"id": "private-id", "hostname": "origin", "literal.dot": "remove-root-literal", "Hostname": "case-sensitive-kept", "unknown_dynamic_key": "unknown-kept", "sequence": i, "literal": map[string]any{"dot": "nested-kept"}}
		actual := policy.FilterFields(source)
		if len(actual) != 4 || actual["Hostname"] != "case-sensitive-kept" || actual["unknown_dynamic_key"] != "unknown-kept" || actual["sequence"] != i || actual["literal"].(map[string]any)["dot"] != "nested-kept" {
			t.Fatalf("output record %d incorrect: %v", i, actual)
		}
		if len(source) != 7 || source["id"] != "private-id" || source["hostname"] != "origin" || source["literal.dot"] != "remove-root-literal" {
			t.Fatalf("output record %d mutated source", i)
		}
	}
	t.Logf("1000000 output maps verified: exactcase/dottedroot removal; unknownkey/nestedvalue preserved; sources unchanged; elapsed=%s", time.Since(start))
}
func FuzzPolicyNeverPanics(f *testing.F) {
	f.Add(sampleLines[1])
	f.Add("{}")
	f.Add("malformed\x00")
	p, _ := Compile([]InputConfig{include("event", "contains", "EHLO")}, nil)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > MaxRawBytes+10 {
			return
		}
		d := p.MatchInput(raw, "", "")
		if len(raw) > MaxRawBytes && d.Allowed {
			t.Fatal(fmt.Sprint(d))
		}
	})
}
