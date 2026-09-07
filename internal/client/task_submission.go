package client

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func (c *Client) createGuestTask(ctx context.Context, daemonID string, request TaskRequest) (TaskEnvelope, error) {
	var empty TaskEnvelope
	if !payloadUUID.MatchString(daemonID) || strings.TrimSpace(request.Prompt) == "" || len(request.Prompt) > 100000 {
		return empty, errs.New("invalid_task", "A workspace UUID and a bounded, nonempty prompt are required.", 2)
	}
	var configuration struct {
		Data struct {
			Folders []struct {
				ID           string `json:"id"`
				RelativePath string `json:"relative_path"`
			} `json:"folders"`
			DefaultAgent   string `json:"default_agent"`
			PermissionMode string `json:"permission_mode"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		} `json:"data"`
	}
	if _, err := c.queryTasks(ctx, daemonID, map[string]any{"operation": "configuration"}, &configuration); err != nil {
		return empty, err
	}
	wanted := "default"
	if request.WorkingDirectory != "" && request.WorkingDirectory != "/workspace" {
		if !strings.HasPrefix(request.WorkingDirectory, "/workspace/") {
			return empty, errs.New("invalid_task", "The working directory must be a registered workspace folder.", 2)
		}
		wanted = strings.TrimPrefix(request.WorkingDirectory, "/workspace/")
	}
	folderID := ""
	for _, folder := range configuration.Data.Folders {
		if !payloadUUID.MatchString(folder.ID) {
			return empty, invalidResponse("guest task folder")
		}
		if folder.RelativePath == wanted {
			if folderID != "" {
				return empty, invalidResponse("ambiguous task folder")
			}
			folderID = folder.ID
		}
	}
	if folderID == "" {
		return empty, errs.New("task_folder_required", "Select a registered workspace folder with --working-directory.", 2)
	}
	agent := request.Agent
	if agent == "" {
		agent = configuration.Data.DefaultAgent
	}
	if agent != "codex" && agent != "opencode" && agent != "cursor" {
		return empty, errs.New("task_agent_unavailable", "Select an agent with supported task execution.", 2)
	}
	permission := request.PermissionMode
	if permission == "" {
		permission = configuration.Data.PermissionMode
	}
	if permission == "approval-auto-deny" {
		permission = "approval"
	}
	if permission != "approval" && permission != "yolo" {
		return empty, errs.New("invalid_task", "The task permission mode is invalid.", 2)
	}
	timeout := request.TimeoutSeconds
	if timeout == 0 {
		timeout = configuration.Data.TimeoutSeconds
	}
	if timeout < 1 || timeout > 1800 {
		return empty, errs.New("invalid_task", "Task timeout must be between 1 and 1800 seconds.", 2)
	}
	operationID, taskID := newAccessOperationID(), newAccessOperationID()
	ticket, err := c.mintAccessTicket(ctx, daemonID, operationID, "tasks.submit", taskID)
	if err != nil {
		return empty, err
	}
	var model any
	if request.Model != "" {
		model = request.Model
	}
	body, err := json.Marshal(map[string]any{"schema": "dr.local-payload", "version": 1,
		"organization_id": ticket.Data.Target.OrganizationID, "workspace_id": daemonID,
		"runtime_generation": ticket.Data.Target.RuntimeGeneration, "assignment_generation": ticket.Data.Target.AssignmentGeneration,
		"payload_id": operationID, "operation_id": operationID, "expected_revision": 0, "kind": "task",
		"document": map[string]any{"task_id": taskID, "agent": agent, "model": model, "permission_mode": permission,
			"folder_id": folderID, "prompt": request.Prompt, "timeout_seconds": timeout, "expected_artifacts": []any{}}})
	if err != nil || len(body) > maximumLocalPayload {
		return empty, errs.New("invalid_task", "The task payload exceeds its limit.", 2)
	}
	u := *c.baseURL
	u.Path, u.RawPath = ticket.Data.GatewayPath, ""
	output := boundedContentJSON{maximum: 128 * 1024}
	if err := c.relayContentType(ctx, ticket.Data.Method, u.String(), ticket.Data.Ticket, "application/vnd.daemons.local-payload+json", bytes.NewReader(body), &output); err != nil {
		return empty, err
	}
	var response struct {
		Receipt json.RawMessage `json:"receipt"`
		Task    struct {
			ID        string `json:"id"`
			AttemptID string `json:"attempt_id"`
			Status    string `json:"status"`
		} `json:"task"`
	}
	if !json.Valid(output.Bytes()) || json.Unmarshal(output.Bytes(), &response) != nil {
		return empty, invalidMutationResponse("guest task receipt")
	}
	receipt, err := decodeLocalPayloadReceipt(response.Receipt, ticket.Data.Target, operationID)
	if err != nil || receipt.Phase != "applied" || response.Task.ID != taskID || !payloadUUID.MatchString(response.Task.AttemptID) || response.Task.Status != "queued" {
		return empty, invalidMutationResponse("guest task receipt")
	}
	result := TaskEnvelope{Data: Task{ID: taskID, DaemonID: daemonID, Agent: agent, Status: "queued", PermissionMode: permission, TimeoutSeconds: WireInt(timeout)},
		Meta: map[string]any{"attempt_id": response.Task.AttemptID, "operation_uuid": operationID}}
	result.Raw, err = json.Marshal(result)
	return result, err
}
