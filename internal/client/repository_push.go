package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

var repositoryUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type RepositoryPush struct {
	RequestUUID         string  `json:"request_uuid"`
	AssignedSubjectUUID string  `json:"assigned_subject_uuid"`
	RepositoryUUID      string  `json:"repository_uuid"`
	PolicyRevisionUUID  string  `json:"policy_revision_uuid"`
	State               string  `json:"state"`
	Version             int64   `json:"version"`
	StatsStatus         string  `json:"stats_status"`
	CommitCount         *int64  `json:"commit_count"`
	FilesChanged        *int64  `json:"files_changed"`
	Insertions          *int64  `json:"insertions"`
	Deletions           *int64  `json:"deletions"`
	RequestedAt         string  `json:"requested_at"`
	ExpiresAt           string  `json:"expires_at"`
	DecidedAt           *string `json:"decided_at"`
	ApprovedUntil       *string `json:"approved_until"`
	ConsumedAt          *string `json:"consumed_at"`
	CompletedAt         *string `json:"completed_at"`
	OutcomeCode         *string `json:"outcome_code"`
}

type RepositoryPushList struct {
	Data       []RepositoryPush `json:"data"`
	NextCursor *string          `json:"next_cursor"`
	Raw        json.RawMessage  `json:"-"`
}

func (response *RepositoryPushList) setRaw(raw json.RawMessage) { response.Raw = raw }

// ListRepositoryPushes reads one bounded metadata page. It never requests local
// summaries, credentials or an approval operation.
func (c *Client) ListRepositoryPushes(ctx context.Context, daemonID, cursor string) (RepositoryPushList, error) {
	var result RepositoryPushList
	if !repositoryUUID.MatchString(daemonID) || (cursor != "" && !repositoryUUID.MatchString(cursor)) {
		return result, invalidResponse("repository identifier")
	}
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	path := "/daemons/" + url.PathEscape(daemonID) + "/push-requests"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, true, "", true, &result); err != nil {
		return RepositoryPushList{}, err
	}
	if err := validateRepositoryPushList(result.Raw, &result); err != nil {
		return RepositoryPushList{}, err
	}
	return result, nil
}

// Validate raw bytes after the general compatibility decoder: that decoder is
// intentionally permissive, while repository metadata has a closed schema.
func validateRepositoryPushList(raw []byte, result *RepositoryPushList) error {
	bad := func() error { return invalidResponse("repository metadata") }
	if len(raw) > 64<<10 || !utf8.Valid(raw) {
		return bad()
	}
	object, ok := repositoryObject(raw, []string{"data", "next_cursor"})
	if !ok {
		return bad()
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(object["data"], &rows); err != nil || rows == nil || len(rows) > 50 {
		return bad()
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return bad()
	}
	if result.NextCursor != nil && (!repositoryUUID.MatchString(*result.NextCursor) || len(rows) != 50) {
		return bad()
	}
	keys := []string{"request_uuid", "assigned_subject_uuid", "repository_uuid", "policy_revision_uuid", "state", "version", "stats_status", "commit_count", "files_changed", "insertions", "deletions", "requested_at", "expires_at", "decided_at", "approved_until", "consumed_at", "completed_at", "outcome_code"}
	seen := map[string]bool{}
	for index, row := range rows {
		if _, ok := repositoryObject(row, keys); !ok {
			return bad()
		}
		item := result.Data[index]
		for _, id := range []string{item.RequestUUID, item.AssignedSubjectUUID, item.RepositoryUUID, item.PolicyRevisionUUID} {
			if !repositoryUUID.MatchString(id) {
				return bad()
			}
		}
		if seen[item.RequestUUID] || item.Version < 1 || item.Version > 9007199254740991 {
			return bad()
		}
		seen[item.RequestUUID] = true
		if !slices.Contains([]string{"pending", "approved", "rejected", "expired", "invalidated", "consumed", "succeeded", "failed", "unknown"}, item.State) {
			return bad()
		}
		if item.StatsStatus != "complete" && item.StatsStatus != "unavailable" {
			return bad()
		}
		for _, count := range []*int64{item.CommitCount, item.FilesChanged, item.Insertions, item.Deletions} {
			if (item.StatsStatus == "unavailable") != (count == nil) || (count != nil && (*count < 0 || *count > 2147483647)) {
				return bad()
			}
		}
		requested, err := time.Parse(time.RFC3339Nano, item.RequestedAt)
		if err != nil {
			return bad()
		}
		expires, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
		if err != nil || expires.Sub(requested) != 15*time.Minute {
			return bad()
		}
		for _, stamp := range []*string{&item.RequestedAt, &item.ExpiresAt, item.DecidedAt, item.ApprovedUntil, item.ConsumedAt, item.CompletedAt} {
			if stamp != nil {
				if len(*stamp) > 27 || len(*stamp) < 20 || (*stamp)[len(*stamp)-1] != 'Z' {
					return bad()
				}
				if _, err := time.Parse(time.RFC3339Nano, *stamp); err != nil {
					return bad()
				}
			}
		}
		if item.OutcomeCode != nil && !slices.Contains([]string{"forbidden", "locked", "stale_generation", "policy_changed", "approval_required", "approval_expired", "request_conflict", "remote_changed", "protected_branch", "rewrite_denied", "remote_denied", "unsupported_transport", "credentials_unavailable", "protection_unavailable", "invalid_payload", "push_failed", "outcome_unknown"}, *item.OutcomeCode) {
			return bad()
		}
	}
	if result.NextCursor != nil && *result.NextCursor != result.Data[len(result.Data)-1].RequestUUID {
		return bad()
	}
	return nil
}

func repositoryObject(raw []byte, keys []string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	result := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(keys, key) {
			return nil, false
		}
		if _, duplicate := result[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		result[key] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(result) != len(keys) {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return result, true
}
