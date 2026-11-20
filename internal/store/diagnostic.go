package store

import (
	"errors"
	"strings"
)

var ErrControllerAuthentication = errors.New("controller metadata authentication rejected")
var ErrPublicAPIKey = errors.New("metadata public API key rejected")
var ErrRPCSchema = errors.New("metadata RPC schema unavailable")

// FailureDiagnostic deliberately excludes upstream messages, credentials and
// project URLs. A failed authenticated read must never become an empty catalog.
func FailureDiagnostic(err error) (string, string, bool) {
	message := ""
	if err != nil {
		message = strings.ToLower(err.Error())
	}
	switch {
	case errors.Is(err, ErrControllerAuthentication), strings.Contains(message, "controller authentication failed"), strings.Contains(message, "http 403"):
		return "controller_secret_mismatch_or_rpc_permission", "Check the controller secret against the existing project owner and RPC grants. Reuse that secret on replacement controllers; do not rebootstrap with a new secret or clear metadata.", false
	case errors.Is(err, ErrPublicAPIKey), strings.Contains(message, "http 401"):
		return "invalid_public_api_key", "Verify the configured Supabase public API key and project URL on this controller.", false
	case errors.Is(err, ErrRPCSchema), strings.Contains(message, "pgrst202"), strings.Contains(message, "schema version"):
		return "schema_missing_or_outdated", "Apply this release's protected RPC schema using the existing controller secret, then retry.", false
	default:
		return "metadata_unavailable", "Check controller connectivity and Supabase availability, then retry. Existing synchronized assets remain authoritative until an approved update succeeds.", true
	}
}
