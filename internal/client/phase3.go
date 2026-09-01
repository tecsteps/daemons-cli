package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Task is the Control Plane task resource returned by the nested
// /daemons/{daemon}/tasks routes. Tasks are always addressed through their
// parent daemon; there is no top-level task route.
type Task struct {
	ID                string         `json:"id"`
	DaemonID          string         `json:"daemon_id"`
	Agent             string         `json:"agent"`
	Model             *string        `json:"model"`
	PermissionMode    string         `json:"permission_mode"`
	WorkingDirectory  string         `json:"working_directory"`
	TimeoutSeconds    WireInt        `json:"timeout_seconds"`
	Status            string         `json:"status"`
	Result            map[string]any `json:"result"`
	ErrorCode         *string        `json:"error_code"`
	CancelRequestedAt *string        `json:"cancel_requested_at"`
	StartedAt         *string        `json:"started_at"`
	FinishedAt        *string        `json:"finished_at"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
}

type TaskEnvelope struct {
	Data Task            `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *TaskEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

type TaskList struct {
	Data []Task          `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *TaskList) setRaw(raw json.RawMessage) { response.Raw = raw }

// TaskRequest carries the fields POST /tasks accepts. Only Prompt is
// required; empty optional fields are omitted so the server applies its own
// defaults (primary agent, /workspace, yolo, default timeout).
type TaskRequest struct {
	Prompt           string
	Agent            string
	Model            string
	PermissionMode   string
	WorkingDirectory string
	TimeoutSeconds   int
}

type FileEntry struct {
	Name  string  `json:"name"`
	Type  string  `json:"type"`
	Size  WireInt `json:"size"`
	MTime WireInt `json:"mtime"`
}

type FileList struct {
	Data []FileEntry `json:"data"`
	Meta struct {
		NextCursor *string `json:"next_cursor"`
	} `json:"meta"`
	Raw json.RawMessage `json:"-"`
}

func (response *FileList) setRaw(raw json.RawMessage) { response.Raw = raw }

type LogLine struct {
	Timestamp *string `json:"timestamp"`
	Level     string  `json:"level"`
	Source    string  `json:"source"`
	Message   string  `json:"message"`
}

type LogList struct {
	Data []LogLine `json:"data"`
	Meta struct {
		NextCursor *string `json:"next_cursor"`
	} `json:"meta"`
	Raw json.RawMessage `json:"-"`
}

func (response *LogList) setRaw(raw json.RawMessage) { response.Raw = raw }

func (c *Client) CreateTask(ctx context.Context, daemonID string, task TaskRequest, idempotencyKey string) (TaskEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return TaskEnvelope{}, err
	}
	body := map[string]any{"prompt": task.Prompt}
	if task.Agent != "" {
		body["agent"] = task.Agent
	}
	if task.Model != "" {
		body["model"] = task.Model
	}
	if task.PermissionMode != "" {
		body["permission_mode"] = task.PermissionMode
	}
	if task.WorkingDirectory != "" {
		body["working_directory"] = task.WorkingDirectory
	}
	if task.TimeoutSeconds > 0 {
		body["timeout_seconds"] = task.TimeoutSeconds
	}
	var result TaskEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/tasks", body, true, idempotencyKey, true, &result)
	if err == nil {
		if field := missingTaskField(result.Data); field != "" {
			return TaskEnvelope{}, invalidMutationResponse("data." + field)
		}
	}
	return result, err
}

func (c *Client) ListTasks(ctx context.Context, daemonID string, limit int) (TaskList, error) {
	requestPath := "/daemons/" + url.PathEscape(daemonID) + "/tasks"
	if limit > 0 {
		requestPath += "?limit=" + strconv.Itoa(limit)
	}
	var result TaskList
	err := c.doJSON(ctx, http.MethodGet, requestPath, nil, true, "", false, &result)
	if err == nil {
		for index, task := range result.Data {
			if field := missingTaskField(task); field != "" {
				return TaskList{}, invalidResponse(fmt.Sprintf("data[%d].%s", index, field))
			}
		}
	}
	return result, err
}

func (c *Client) ShowTask(ctx context.Context, daemonID, taskID string) (TaskEnvelope, error) {
	var result TaskEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/daemons/"+url.PathEscape(daemonID)+"/tasks/"+url.PathEscape(taskID), nil, true, "", false, &result)
	if err == nil {
		if field := missingTaskField(result.Data); field != "" {
			return TaskEnvelope{}, invalidResponse("data." + field)
		}
	}
	return result, err
}

func (c *Client) CancelTask(ctx context.Context, daemonID, taskID, idempotencyKey string) (TaskEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return TaskEnvelope{}, err
	}
	var result TaskEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/tasks/"+url.PathEscape(taskID)+"/cancel", nil, true, idempotencyKey, true, &result)
	if err == nil {
		if field := missingTaskField(result.Data); field != "" {
			return TaskEnvelope{}, invalidMutationResponse("data." + field)
		}
	}
	return result, err
}

// ListFiles reads one page of a workspace directory listing. The cursor is
// opaque and comes from the previous page's meta.next_cursor.
func (c *Client) ListFiles(ctx context.Context, daemonID, workspacePath, cursor string, limit int) (FileList, error) {
	query := url.Values{}
	if workspacePath != "" {
		query.Set("path", workspacePath)
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	requestPath := "/daemons/" + url.PathEscape(daemonID) + "/files"
	if encoded := query.Encode(); encoded != "" {
		requestPath += "?" + encoded
	}
	var result FileList
	err := c.doJSON(ctx, http.MethodGet, requestPath, nil, true, "", false, &result)
	if err == nil {
		for index, entry := range result.Data {
			if entry.Name == "" || entry.Type == "" {
				field := "name"
				if entry.Name != "" {
					field = "type"
				}
				return FileList{}, invalidResponse(fmt.Sprintf("data[%d].%s", index, field))
			}
		}
	}
	return result, err
}

func missingTaskField(task Task) string {
	switch {
	case task.ID == "":
		return "id"
	case task.Status == "":
		return "status"
	default:
		return ""
	}
}

// ListLogs reads one bounded, server-redacted log snapshot. The source is
// validated by the caller against the closed set the server accepts.
func (c *Client) ListLogs(ctx context.Context, daemonID, source, level, cursor string, limit int) (LogList, error) {
	query := url.Values{}
	query.Set("source", source)
	if level != "" {
		query.Set("level", level)
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var result LogList
	err := c.doJSON(ctx, http.MethodGet, "/daemons/"+url.PathEscape(daemonID)+"/logs?"+query.Encode(), nil, true, "", false, &result)
	return result, err
}
