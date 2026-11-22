package catalog

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"nexora.local/nli-v20/internal/canonicaljson"
)

// BuiltinPayload is the release envelope persisted for the original catalog
// asset. Controller seeding and the runtime reference check share these bytes.
func BuiltinPayload(asset Asset) ([]byte, error) {
	return json.Marshal(map[string]any{
		"name": asset.Name, "config": asset.Config,
		"review_state": "active", "approved_by": "nli-v21-release",
		"published_by": "nli-v21-release",
	})
}

type embeddedReferenceKey struct{ collection, id string }

type embeddedReference struct {
	packID  string
	payload []byte
}

var embeddedReferences = sync.OnceValue(func() map[embeddedReferenceKey]embeddedReference {
	assets, err := Assets()
	if err != nil {
		return nil
	}
	packByFamily := map[string]string{}
	for _, asset := range assets {
		family, eventTemplate := strings.CutSuffix(asset.ID, "-event-template")
		packID, _ := asset.Config["parser_pack_id"].(string)
		if asset.Collection == "templates" && eventTemplate && packID != "" && asset.Config["layout_stage"] != nil {
			packByFamily[family] = packID
		}
	}
	references := map[embeddedReferenceKey]embeddedReference{}
	for _, asset := range assets {
		collection, suffix := asset.Collection, "-event-template"
		switch collection {
		case "templates":
		case "kv":
			if asset.Config["input_field"] != "_kv_tail" {
				continue
			}
			collection = "kv-config"
			suffix = "-mixed-kv"
		default:
			continue
		}
		family, matched := strings.CutSuffix(asset.ID, suffix)
		packID := packByFamily[family]
		if !matched || packID == "" {
			continue
		}
		payload, err := BuiltinPayload(asset)
		if err != nil {
			continue
		}
		canonical, err := canonicaljson.Normalize(payload)
		if err == nil {
			references[embeddedReferenceKey{collection, asset.ID}] = embeddedReference{packID, canonical}
		}
	}
	return references
})

// EmbeddedReferencePackID recognizes the exact original revision of a
// ParserPack stage reference. The synchronized asset remains in the bundle
// and the named embedded pack owns its runtime behavior.
func EmbeddedReferencePackID(collection, id string, revision int, payload []byte) string {
	if revision != 1 || (collection != "templates" && collection != "kv-config") {
		return ""
	}
	reference, exists := embeddedReferences()[embeddedReferenceKey{collection, id}]
	if !exists {
		return ""
	}
	canonical, err := canonicaljson.Normalize(payload)
	if err != nil || !bytes.Equal(canonical, reference.payload) {
		return ""
	}
	return reference.packID
}
