package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const repositoryFixtureUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func TestRepositoryBranchValidationMatchesFullReferenceConstraints(t *testing.T) {
	for _, branch := range []string{"feature", "feature/nested", "feature/日本語", strings.Repeat("a", 244)} {
		if !ValidRepositoryBranch(branch) {
			t.Error("valid branch rejected")
		}
	}
	for _, branch := range []string{"", "feature..old", ".hidden", "x/.hidden", "x.lock", "x/", "x//y", "x.", "x@{1}", "x~1", "x^", "x:y", "x?", "x*", "x[", "x\\y", "x\ny", strings.Repeat("a", 245), string([]byte{0xff})} {
		if ValidRepositoryBranch(branch) {
			t.Error("invalid branch accepted")
		}
	}
}

func repositoryMetadataFixture(t *testing.T) string {
	t.Helper()
	one := int64(1)
	page := RepositoryPushList{Data: []RepositoryPush{{
		RequestUUID: repositoryFixtureUUID, AssignedSubjectUUID: repositoryFixtureUUID,
		RepositoryUUID: repositoryFixtureUUID, PolicyRevisionUUID: repositoryFixtureUUID,
		State: "pending", Version: 1, StatsStatus: "complete", CommitCount: &one,
		FilesChanged: &one, Insertions: &one, Deletions: &one,
		RequestedAt: "2026-09-08T12:00:00.000000Z", ExpiresAt: "2026-09-08T12:15:00.000000Z",
	}}}
	data, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRepositoryMetadataUsesOnlyAuthenticatedCentralRead(t *testing.T) {
	fixture := repositoryMetadataFixture(t)
	called := 0
	api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/daemons/"+repositoryFixtureUUID+"/push-requests" || r.URL.Query().Get("cursor") != repositoryFixtureUUID || r.Header.Get("Authorization") == "" {
			t.Error("unexpected repository metadata request")
		}
		io.WriteString(w, fixture)
	})
	page, err := api.ListRepositoryPushes(context.Background(), repositoryFixtureUUID, repositoryFixtureUUID)
	if err != nil || len(page.Data) != 1 || page.Data[0].State != "pending" || string(page.Raw) != fixture || called != 1 {
		t.Fatalf("metadata read failed: %v", err)
	}
	if _, err := api.ListRepositoryPushes(context.Background(), "../unsafe", ""); err == nil || called != 1 {
		t.Fatal("invalid identity reached transport")
	}
}

func TestRepositoryMetadataRejectsUntrustedRawFields(t *testing.T) {
	fixture := repositoryMetadataFixture(t)
	cases := map[string]string{
		"extra":              strings.Replace(fixture, `"state":"pending"`, `"state":"pending","branch":"private-canary"`, 1),
		"duplicate":          strings.Replace(fixture, `"state":"pending"`, `"state":"pending","st\u0061te":"approved"`, 1),
		"envelope duplicate": strings.TrimSuffix(fixture, "}") + `,"next_cursor":null}`,
		"missing":            strings.Replace(fixture, `"outcome_code":null`, `"unused":null`, 1),
		"numeric string":     strings.Replace(fixture, `"version":1`, `"version":"1"`, 1),
		"fraction":           strings.Replace(fixture, `"version":1`, `"version":1.0`, 1),
		"unknown state":      strings.Replace(fixture, `"state":"pending"`, `"state":"pushing"`, 1),
		"unknown outcome":    strings.Replace(fixture, `"outcome_code":null`, `"outcome_code":"private-canary"`, 1),
		"count overflow":     strings.Replace(fixture, `"insertions":1`, `"insertions":2147483648`, 1),
		"missing count":      strings.Replace(fixture, `"insertions":1`, `"insertions":null`, 1),
		"mixed unavailable":  strings.Replace(fixture, `"stats_status":"complete"`, `"stats_status":"unavailable"`, 1),
		"bad expiry":         strings.Replace(fixture, "12:15:00", "12:16:00", 1),
		"bad cursor":         strings.Replace(fixture, `"next_cursor":null`, `"next_cursor":"1"`, 1),
		"trailing":           fixture + "{}",
		"oversized":          fixture + strings.Repeat(" ", 64<<10),
		"invalid utf8":       strings.TrimSuffix(fixture, "}") + ",\"canary\":\"\xff\"}",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, raw) })
			if _, err := api.ListRepositoryPushes(context.Background(), repositoryFixtureUUID, ""); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}

func TestRepositoryMetadataBoundsRowsAndPermitsUnavailableCounts(t *testing.T) {
	fixture := repositoryMetadataFixture(t)
	var page RepositoryPushList
	if err := json.Unmarshal([]byte(fixture), &page); err != nil {
		t.Fatal(err)
	}
	page.Data[0].StatsStatus = "unavailable"
	page.Data[0].CommitCount, page.Data[0].FilesChanged, page.Data[0].Insertions, page.Data[0].Deletions = nil, nil, nil, nil
	data, _ := json.Marshal(page)
	if err := validateRepositoryPushList(data, &RepositoryPushList{}); err != nil {
		t.Fatal(err)
	}
	for len(page.Data) < 51 {
		page.Data = append(page.Data, page.Data[0])
	}
	data, _ = json.Marshal(page)
	if err := validateRepositoryPushList(data, &RepositoryPushList{}); err == nil {
		t.Fatal("oversized page accepted")
	}
	page.Data = page.Data[:2]
	data, _ = json.Marshal(page)
	if err := validateRepositoryPushList(data, &RepositoryPushList{}); err == nil {
		t.Fatal("duplicate request accepted")
	}
}
