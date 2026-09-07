package client

import "github.com/tecsteps/daemons-cli/internal/errs"

// LocalPayloadUnavailable fails before reading content or submitting a create.
// The guest importer exists, but API v1 has no authorized receipt/stream route.
// A normal file upload must never substitute for that lifecycle boundary.
func LocalPayloadUnavailable() error {
	return errs.New("local_payload_unavailable", "The API does not publish the E4 local payload receipt and streaming endpoints yet. Content remains on your device; no create or upload was submitted.", 2)
}
