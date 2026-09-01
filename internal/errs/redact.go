package errs

import "regexp"

// credentialPattern matches every credential shape the CLI can meet: Control
// Plane, Agent API, terminal, and ticket tokens, an optional "Bearer" prefix,
// and the "dr.<ticket>" WebSocket subprotocol form the gateway uses.
var credentialPattern = regexp.MustCompile(`(?i)(?:bearer[ \t]+)?dr[_.](?:cp|agent|terminal|ticket)_[A-Za-z0-9._~-]+`)

// Redact replaces any embedded credential with a fixed marker. Every package
// that turns a transport, gateway, or file error into user-visible text
// passes it through here so a token can never reach stdout, stderr, or a
// JSON report.
func Redact(value string) string {
	return credentialPattern.ReplaceAllString(value, "[REDACTED]")
}
