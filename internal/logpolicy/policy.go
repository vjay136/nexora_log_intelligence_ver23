// Package logpolicy compiles optional record admission and customer-output
// policies. It never executes a parser, performs I/O, or mutates caller fields.
package logpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	Capability      = "log-policies-v1"
	MaxPolicies     = 128
	MaxRules        = 64
	MaxValues       = 128
	MaxTerms        = 8192
	MaxOutputFields = 10000
	MaxRawBytes     = 1 << 20
)

type Rule struct {
	Field         string   `json:"field"`
	Operator      string   `json:"operator"`
	Values        []string `json:"values"`
	CaseSensitive bool     `json:"case_sensitive"`
}
type InputConfig struct {
	ID        string `json:"id,omitempty"`
	Enabled   bool   `json:"enabled"`
	MatchMode string `json:"match_mode"`
	Rules     []Rule `json:"rules"`
}
type OutputConfig struct {
	ID      string   `json:"id,omitempty"`
	Enabled bool     `json:"enabled"`
	Fields  []string `json:"fields"`
}
type Decision struct {
	Allowed          bool     `json:"allowed"`
	PolicyError      bool     `json:"policy_error,omitempty"`
	MatchedPolicyIDs []string `json:"matched_policy_ids,omitempty"`
	Reason           string   `json:"reason,omitempty"`
}
type inputPolicy struct {
	id, mode string
	rules    []Rule
}
type Set struct {
	inputs   []inputPolicy
	removed  map[string]struct{}
	metadata bool
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func ValidateInput(config InputConfig) error {
	if config.MatchMode != "any" && config.MatchMode != "all" {
		return errors.New("match_mode must be any or all")
	}
	if len(config.Rules) > MaxRules || config.Enabled && len(config.Rules) == 0 {
		return errors.New("enabled input policy requires 1..64 rules")
	}
	for _, rule := range config.Rules {
		switch rule.Field {
		case "keyword", "year", "hostname", "service", "event_type", "loglevel", "event":
		default:
			return fmt.Errorf("unsupported selective field %q", rule.Field)
		}
		switch rule.Operator {
		case "equals", "contains", "prefix":
		default:
			return errors.New("operator must be equals, contains or prefix")
		}
		if len(rule.Values) == 0 || len(rule.Values) > MaxValues {
			return errors.New("each rule requires 1..128 literal values")
		}
		for _, value := range rule.Values {
			if !validText(value, 256) {
				return errors.New("filter values must be 1..256 UTF-8 bytes without control characters")
			}
		}
	}
	return nil
}
func ValidateOutput(config OutputConfig) error {
	if len(config.Fields) > MaxOutputFields || config.Enabled && len(config.Fields) == 0 {
		return errors.New("enabled output policy requires 1..10000 exact field names")
	}
	seen := map[string]bool{}
	for _, field := range config.Fields {
		if !validText(field, 128) {
			return errors.New("output fields must be 1..128 UTF-8 bytes without control characters")
		}
		if seen[field] {
			return fmt.Errorf("duplicate exact output field %q", field)
		}
		seen[field] = true
	}
	return nil
}
func Compile(inputs []InputConfig, outputs []OutputConfig) (*Set, error) {
	if len(inputs) > MaxPolicies || len(outputs) > MaxPolicies {
		return nil, errors.New("at most 128 input and 128 output policy profiles are supported")
	}
	set := &Set{removed: map[string]struct{}{}}
	terms := 0
	for index, config := range inputs {
		if err := ValidateInput(config); err != nil {
			return nil, err
		}
		if !config.Enabled {
			continue
		}
		p := inputPolicy{id: config.ID, mode: config.MatchMode}
		if p.id == "" {
			p.id = fmt.Sprintf("input-%d", index+1)
		}
		for _, original := range config.Rules {
			rule := original
			rule.Values = append([]string(nil), original.Values...)
			for i, value := range rule.Values {
				if !rule.CaseSensitive {
					rule.Values[i] = strings.ToLower(value)
				}
			}
			terms += len(rule.Values)
			if rule.Field != "keyword" {
				set.metadata = true
			}
			p.rules = append(p.rules, rule)
		}
		set.inputs = append(set.inputs, p)
	}
	if terms > MaxTerms {
		return nil, errors.New("selective policies exceed 8192 total literal values")
	}
	for _, config := range outputs {
		if err := ValidateOutput(config); err != nil {
			return nil, err
		}
		if !config.Enabled {
			continue
		}
		for _, field := range config.Fields {
			set.removed[field] = struct{}{}
		}
	}
	if len(set.removed) > MaxOutputFields {
		return nil, errors.New("output policies exceed 10000 distinct removed fields")
	}
	return set, nil
}
func (s *Set) InputEnabled() bool  { return s != nil && len(s.inputs) > 0 }
func (s *Set) OutputEnabled() bool { return s != nil && len(s.removed) > 0 }
func (s *Set) MatchInput(raw, service, hostname string) Decision {
	return s.MatchInputRecord(raw, service, hostname, false)
}
func (s *Set) MatchInputRecord(raw, service, hostname string, incomplete bool) Decision {
	if !s.InputEnabled() {
		return Decision{Allowed: true, Reason: "selective input disabled"}
	}
	if len(raw) > MaxRawBytes || incomplete {
		return Decision{Allowed: false, PolicyError: true, Reason: "active input policy cannot evaluate an incomplete or oversized record; excluded before parsing"}
	}
	var metadata map[string]string
	if s.metadata {
		metadata = Metadata(raw, service, hostname)
	}
	lowerRaw := ""
	lowered := false
	for _, policy := range s.inputs {
		matched := policy.mode == "all"
		for _, rule := range policy.rules {
			value := raw
			if rule.Field != "keyword" {
				value = metadata[rule.Field]
			}
			if !rule.CaseSensitive {
				if rule.Field == "keyword" {
					if !lowered {
						lowerRaw = strings.ToLower(raw)
						lowered = true
					}
					value = lowerRaw
				} else {
					value = strings.ToLower(value)
				}
			}
			found := false
			for _, wanted := range rule.Values {
				switch rule.Operator {
				case "equals":
					found = value == wanted
				case "contains":
					found = strings.Contains(value, wanted)
				case "prefix":
					found = strings.HasPrefix(value, wanted)
				}
				if found {
					break
				}
			}
			if policy.mode == "all" {
				matched = matched && found
				if !matched {
					break
				}
			} else {
				matched = matched || found
				if matched {
					break
				}
			}
		}
		if matched {
			return Decision{Allowed: true, MatchedPolicyIDs: []string{policy.id}, Reason: "matched selective input policy"}
		}
	}
	return Decision{Allowed: false, Reason: "no enabled selective input policy matched"}
}

// FilterFields removes exact root keys and returns a new map when enabled. A
// literal key containing a dot is not interpreted as an arbitrary JSON path.
func (s *Set) FilterFields(fields map[string]any) map[string]any {
	if !s.OutputEnabled() || fields == nil {
		return fields
	}
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		if _, drop := s.removed[key]; !drop {
			result[key] = value
		}
	}
	return result
}

var nativeHeader = regexp.MustCompile(`^\s*(\d{8})\s+\d{9}[+-]\d{4}\s+(\S+)\s+(\S+)\s+`)
var isoHeader = regexp.MustCompile(`^\s*(\d{4})-\d{2}-\d{2}[T ]`)
var kvMetadata = regexp.MustCompile(`(?:^|[\s;,])([A-Za-z_][A-Za-z0-9_.-]{0,127})\s*=\s*("[^"\r\n]*"|'[^'\r\n]*'|[^\s;,]+)`)
var firstAssignment = regexp.MustCompile(`(?:^|[\s;])(?:[A-Za-z_][A-Za-z0-9_.-]{0,127})\s*[=:]`)

// Metadata is deliberately a bounded routing/header inspection, not successful
// parser output. Unknown fields remain empty and cannot fabricate a match.
func Metadata(raw, service, hostname string) map[string]string {
	m := map[string]string{"service": service, "hostname": hostname}
	line, _, _ := strings.Cut(raw, "\n")
	line = strings.TrimSuffix(line, "\r")
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "{") && len(trimmed) <= MaxRawBytes {
		var object map[string]json.RawMessage
		if json.Unmarshal([]byte(trimmed), &object) == nil {
			for key, encoded := range object {
				var text string
				if json.Unmarshal(encoded, &text) != nil {
					var number json.Number
					if json.Unmarshal(encoded, &number) != nil {
						continue
					}
					text = string(number)
				}
				putMetadata(m, key, text)
			}
			return m
		}
	}
	native := false
	if match := nativeHeader.FindStringSubmatchIndex(line); len(match) == 8 {
		native = true
		m["year"], m["hostname"], m["service"] = line[match[2]:match[2]+4], line[match[4]:match[5]], line[match[6]:match[7]]
		header := line
		if assignment := firstAssignment.FindStringIndex(line[match[1]:]); assignment != nil {
			header = line[:match[1]+assignment[0]]
		}
		parts := strings.Split(strings.TrimSpace(header), ";")
		if len(parts) > 1 {
			words := strings.Fields(parts[0])
			level := ""
			if len(words) > 0 {
				level = words[len(words)-1]
			}
			if numeric(level) && len(parts) > 2 {
				level = strings.TrimSpace(parts[1])
			}
			m["event_type"], m["loglevel"] = level, level
			event := strings.TrimSpace(parts[len(parts)-1])
			if at := strings.IndexByte(event, '('); at >= 0 {
				event = event[:at]
			}
			m["event"] = event
		}
	} else if match := isoHeader.FindStringSubmatch(line); len(match) > 1 {
		m["year"] = match[1]
	}
	if native {
		// Tail keys are customer data, so do not scan them for routing metadata.
		return m
	}
	for _, parts := range kvMetadata.FindAllStringSubmatch(line, 128) {
		value := parts[2]
		if len(value) > 1 && (value[0] == '"' || value[0] == '\'') {
			value = value[1 : len(value)-1]
		}
		putMetadata(m, parts[1], value)
	}
	return m
}
func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func putMetadata(m map[string]string, key, value string) {
	switch strings.ToLower(key) {
	case "hostname", "host":
		m["hostname"] = value
	case "service":
		m["service"] = value
	case "year":
		m["year"] = value
	case "date", "timestamp", "@timestamp":
		if len(value) >= 4 && numeric(value[:4]) {
			m["year"] = value[:4]
		}
	case "event_type":
		m["event_type"] = value
	case "loglevel", "level", "severity":
		m["loglevel"] = value
	case "event", "event_name":
		if at := strings.IndexByte(value, '('); at >= 0 {
			value = value[:at]
		}
		m["event"] = value
	}
}
