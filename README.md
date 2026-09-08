# daemons CLI

The `daemons` command-line client is distributed as self-contained macOS and Linux binaries. The first beta is unsigned and not notarized; it is not described as signed anywhere in these instructions.

## Install from a GitHub Release

This is the supported installation path. It needs neither Go, Node, a package manager, nor a checkout of this repository.

1. Open the [latest release](https://github.com/tecsteps/daemons-cli/releases/latest) and choose the asset matching your system:

   | System | Asset |
   | --- | --- |
   | macOS on Intel | `daemons_vX.Y.Z_darwin_amd64.zip` |
   | macOS on Apple silicon | `daemons_vX.Y.Z_darwin_arm64.zip` |
   | Linux on x86-64 | `daemons_vX.Y.Z_linux_amd64.tar.gz` |
   | Linux on ARM64 | `daemons_vX.Y.Z_linux_arm64.tar.gz` |

   Download that archive and the `SHA256SUMS` file from the same release. Release archive names always use `daemons_vVERSION_OS_ARCH`, with ZIP for macOS and tar.gz for Linux. Every archive contains `daemons`, `LICENSE`, and `NOTICE`.

2. Verify the archive before extracting it. Replace `ARCHIVE` with the downloaded filename.

   On macOS:

   ```sh
   grep -F "  ARCHIVE" SHA256SUMS | shasum -a 256 -c -
   ```

   On Linux:

   ```sh
   grep -F "  ARCHIVE" SHA256SUMS | sha256sum -c -
   ```

   The command must report `OK`. Stop if it does not.

3. Extract the archive and install the executable in a directory on your `PATH` (the example uses `~/.local/bin`).

   On macOS:

   ```sh
   unzip ARCHIVE
   mkdir -p "$HOME/.local/bin"
   install -m 0755 daemons "$HOME/.local/bin/daemons"
   ```

   On Linux:

   ```sh
   tar -xzf ARCHIVE
   mkdir -p "$HOME/.local/bin"
   install -m 0755 daemons "$HOME/.local/bin/daemons"
   ```

   If needed, add the directory to your shell startup file and start a new shell:

   ```sh
   export PATH="$HOME/.local/bin:$PATH"
   ```

4. On macOS, Gatekeeper can block this temporary unsigned, unnotarized beta when the downloaded file has the `com.apple.quarantine` attribute. After the checksum succeeds, remove the attribute only when it is present:

   ```sh
   if xattr -p com.apple.quarantine "$HOME/.local/bin/daemons" >/dev/null 2>&1; then
       xattr -d com.apple.quarantine "$HOME/.local/bin/daemons"
   fi
   ```

   This is a temporary beta fallback while Developer ID signing and Apple notarization credentials are unavailable. It is not needed for a future signed and notarized release.

5. Confirm the installation:

   ```sh
   daemons --version
   ```

## Commands

Run `daemons help` for the full list. Every command accepts `--help`. Global options: `--json` (canonical API document on stdout), `--quiet`, `--host URL`, `--no-color`, `--request-id ID`.

### Reads

| Command | API route | Scope |
| --- | --- | --- |
| `daemons whoami` | `GET /api/v1/me` | `control-plane:discover` |
| `daemons capabilities` | `GET /api/v1/capabilities` | `control-plane:discover` |
| `daemons list` (alias `ls`) / `show ID` | `GET /api/v1/daemons[/{daemon}]` | `daemons:read` |
| `daemons operations list [--limit N]` | `GET /api/v1/operations?limit=N` (1 to 200) | `operations:read` |
| `daemons operations show ID` | `GET /api/v1/operations/{operation}` | `operations:read` |

`daemons show ID` prints the daemon's current `ETag`; `daemons destroy` uses that value for its conditional delete.

### Tasks, files, and logs

Tasks, workspace listings, and logs are always addressed through their daemon. `DAEMON` is the daemon UUID or its exact name.

| Command | API route | Scope |
| --- | --- | --- |
| `daemons task run DAEMON (PROMPT \| -) [--agent AGENT] [--model MODEL] [--permission-mode yolo\|approval-auto-deny] [--working-directory /workspace/DIR] [--timeout SECONDS]` | `POST /api/v1/daemons/{daemon}/tasks` | `tasks:write` |
| `daemons task show DAEMON TASK` | `GET /api/v1/daemons/{daemon}/tasks/{task}` | `tasks:read` |
| `daemons task list DAEMON [--limit N]` | `GET /api/v1/daemons/{daemon}/tasks` | `tasks:read` |
| `daemons task cancel DAEMON TASK` | `POST /api/v1/daemons/{daemon}/tasks/{task}/cancel` | `tasks:cancel` |
| `daemons files list DAEMON [PATH] [--cursor CURSOR] [--limit N] [--all]` | `GET /api/v1/daemons/{daemon}/files` | `files:read` |
| `daemons logs DAEMON --source agent\|app\|daemon\|provisioning [--level LEVEL] [--cursor CURSOR] [--limit N]` | `GET /api/v1/daemons/{daemon}/logs` | `logs:read` |

Pass `-` as the prompt to read it from stdin (`cat brief.md | daemons task run research -`), which keeps it out of shell history and process listings. `task run` and `task cancel` are mutations and follow the idempotency-key rules below; a Codex task in YOLO mode may answer `confirmation_required`. A task that ended `failed`, `cancelled`, or `timed_out` makes `task show` exit 1 under the task's `error_code`. There is no `--wait` or `--follow` for tasks yet: poll with `task show`.

`files list` is an inventory only (name, type, size, mtime); it never downloads content. One page is printed per call with the next cursor on stderr; `--all` follows cursors for up to 50 pages and then stops with a resumable cursor. In `--json` mode every page is written as its own canonical document.

`logs` prints one bounded, server-redacted snapshot. `--source` is required and validated locally against the closed set; `--follow` is refused because the Control Plane has no log event route yet. Rerun with the printed `--cursor` to read newer lines.

### Mutations

Every mutation takes `--idempotency-key KEY` (8 to 128 characters of letters, digits, `.`, `_`, `:`, `-`). Interactively the CLI generates one, prints it on stderr before submitting, and reuses it for the whole command. With `--json` or without a terminal an explicit key is required, so a script can never retry under a fresh key by accident. Every mutation also performs the API version preflight (`GET /api/v1`, scope `control-plane:discover`).

| Command | API route | Scope |
| --- | --- | --- |
| `daemons create NAME --size small\|medium\|large --variant burstable\|reserved --agent AGENT --assigned-user UUID --creation-team UUID` | `POST /api/v1/daemons` | `daemons:write` |
| `daemons start\|stop\|pause\|resume ID [--etag ETAG]` | `POST /api/v1/daemons/{daemon}/{action}` with `If-Match` | `daemons:write` |
| `daemons restart ID [--force] [--etag ETAG]` | `POST /api/v1/daemons/{daemon}/restart`, `{force:false\|true}` | `daemons:write` |
| `daemons resize ID --size SIZE --accepted-offer UUID [--etag ETAG]` | `POST /api/v1/daemons/{daemon}/resize`, `{size,accepted_offer_id}` | `daemons:write` |
| `daemons delete ID [--etag ETAG]` | `DELETE /api/v1/daemons/{daemon}` with `If-Match` and browser approval | `daemons:destroy` |
| `daemons rename ID NAME [--etag ETAG]` | `PATCH /api/v1/daemons/{daemon}`, `{name}` with `If-Match` | `daemons:write` |
| `daemons stop UUID...` | `POST /api/v1/daemons/bulk/stop`, `{daemon_ids:[...]}` | `daemons:write` |
| `daemons operations cancel\|retry ID` | `POST /api/v1/operations/{operation}/{action}` | `daemons:write` plus workspace capability |
| `daemons operations wait ID [--wait-timeout DURATION]` | `GET /api/v1/operations/{operation}` | `operations:read` |

`spawn` aliases `create`, `destroy` aliases `delete`, `status` aliases `show`, and `force-restart` aliases `restart --force`. `retry ID` targets an operation, as does `operations retry ID`. Customer server commands, server selection and disk quota flags are removed. Workspace displays have no server column. Use exact workspace UUIDs for lifecycle commands.

Create sends only metadata. Optional flags are `--source empty|payload`, `--team UUID` and `--accepted-offer UUID`; source defaults to `empty`. The assignee and creation team are required, and the optional grouping team does not replace the creation team. The API currently returns only `meta.operation.uuid` on create; `--wait` polls that ID. Accepted offers are references to approved prices, never client-supplied monetary amounts. Resize is upward only while Running (or supported disk-full Unhealthy), with no variant switch. Stop retains compute at the active price; Pause releases compute at the paused price.

The published API does not yet expose E4's authorized local payload receipt and streaming endpoints. `create --repo URL [--branch BRANCH]`, `create --payload-file PATH`, and `operations continue ID --payload-file PATH` fail before any create, file read or upload. Metadata-only `--source payload` remains available for an assignee using a separate authorized uploader; the CLI warns that its own uploader is unavailable. Content stays on the device; the payload deadline is 15 minutes after target readiness, never during a capacity wait. The CLI does not upload repository input to metadata or ordinary file endpoints. Additional agents, labels and descriptions are also not accepted by the landed create API and have no CLI flags yet.

Force restart sends `force:true` and preserves the API's confirmation denial; the current API always denies force and supplies no approval URL. Bulk delete is refused locally because the landed `/daemons/bulk/destroy` endpoint does not enforce confirmation bound to the complete UUID/revision set. Single delete retains browser approval. These are upstream integration gaps, not completed lifecycle capabilities.

Bulk stop normalizes and deduplicates exact UUIDs in one request so the API can reject a denied selection before any mutation. Every returned outcome is printed, including failures. A partial failure exits 1; `--wait` polls all accepted child operations within one total timeout. Missing outcomes produce exit 8. The bulk API does not currently accept per-item ETags.

Single-workspace lifecycle commands, rename and delete read the daemon to capture its `ETag` and send it as `If-Match`. Pass `--etag` to pin a value and skip the read. A stale precondition exits 1 without resubmitting. Delete also re-reads to explain the changed state. Replay guidance preserves the original command options, ETag and idempotency key. Browser approval never creates a replacement key.

### Waiting for the API

- E4 local payload receipt lookup and streaming routes are not published. Repository and payload-file commands fail before creating a workspace, reading a file or uploading content.
- Bulk delete lacks confirmation bound to the complete UUID/revision set on `/daemons/bulk/destroy`. The CLI refuses bulk deletion before sending any request.
- Force restart currently returns the API's confirmation denial without an approval URL. Additional agents, labels and descriptions are not accepted by the create API, and bulk stop does not accept per-item ETags.

### Waiting for operations

Add `--wait` to any mutation to poll its operation until it reaches a terminal state (`succeeded`, `failed`, `partially_succeeded`, `cancelled`, `timed_out`, or `outcome_unknown`). Polling honours `Retry-After`, otherwise backs off from 2s to 15s with jitter. `--wait-timeout` bounds the wait (default `10m`); use a duration such as `1s` or `10m`, or a bare number of seconds such as `90`. Ctrl-C stops waiting locally; it never cancels the operation on the server.

In `--json` mode with `--wait`, stdout carries the mutation's document first and, once polling ends, the final operation document on its own line. Progress lines go to stderr and are suppressed by `--quiet`.

Outcomes: `partially_succeeded` is reported as a failure (exit 1) with the operation's `result` printed so you can see what landed. A wait that hits its timeout exits 8 with the last known state and the `daemons operations show ID` command to check it.

### Confirmation and unknown outcomes

When the API answers `409 confirmation_required` (for example on `daemons destroy`), nothing has changed. The CLI prints the safe summary, the approval URL, the expiry and the confirmation ID, and exits 6. In an interactive terminal it offers to open the approval URL in your browser; opening it is never treated as consent, and the CLI never polls or approves on your behalf. Approve in the browser, then run the same command again. With `--json` the canonical problem document is written to stdout and no browser is opened.

When a mutation's outcome cannot be determined (a transport failure after dispatch, an invalid response, or an operation ending in `outcome_unknown`), the CLI exits 8 and prints the reconciliation step to run first (for example `daemons list` after a spawn, `daemons show ID` after a lifecycle action) and the exact replay command with the original idempotency key. It never retries a possibly destructive or billable mutation on its own, and never under a new key.

### Authentication and credentials

`daemons login` runs the device flow. `daemons login --token-stdin` reads an existing Control Plane token from stdin instead (one line), verifies it with `GET /api/v1/me`, and stores it; a token is never accepted as an argument and never echoed. `DAEMONS_TOKEN` in the environment overrides the store for CI and is never written to disk.

Credentials live in an owner-only file (`~/.config/daemons/credentials.json`, or `DAEMONS_CREDENTIALS_FILE`) keyed by normalized host, so logging in to a second `--host` never overwrites the first. Without `--host` or `DAEMONS_HOST` the CLI uses the production host when it has a credential, otherwise the only stored host; two or more non-production hosts require an explicit `--host`. `daemons logout` revokes and removes only the current host's credential. A credential file from an older release is migrated on the next login.

### Workspace lock

A protected workspace refuses every access kind until the guest itself verifies a PIN. That verification is not a Control Plane check: `daemons unlock DAEMON` opens a finite encrypted exchange straight to the guest, and no PIN, verifier, recovery phrase or device proof reaches daemons.run at any point.

```sh
daemons lock pair DAEMON        # compare and pin the guest identity
daemons unlock DAEMON           # hidden PIN prompt, installs an 8 hour device grant
daemons lock status DAEMON
daemons lock DAEMON             # give up this device's grant
daemons lock setup|change|recover DAEMON
```

Secrets are typed at a hidden prompt and nowhere else. There is deliberately no flag, environment variable or piped stdin that carries a PIN or a recovery phrase, naming one (`--pin`, `--secret`, ...) is a usage error, and a non-interactive run refuses with exit 2 rather than falling back.

`lock pair` shows the guest's public identity pin so it can be compared with an already trusted device before anything is committed to it; the probe sends no request frame. `unlock --trust-on-first-use` accepts the offered identity without that comparison and says so: it is a disclosed bootstrap, not a verified pairing. A changed identity always fails closed with `lock_identity_changed` and needs an explicit `lock pair`.

A grant lasts eight hours from verification with no sliding refresh, and it never survives a guest reboot, an explicit lock, a PIN change, a recovery or a reassignment. It lives in an owner-only 0600 file (`~/.config/daemons/workspace-lock.json`, or `DAEMONS_WORKSPACE_LOCK_FILE`) holding the public identity pin and, while the grant is live, the device signing key; `daemons logout` and `daemons lock pair --forget` remove it. The PIN itself is never written there.

`lock status` reports what this device knows. Guest state is shown as `unknown` unless the guest itself reported it: it is never inferred from Control Plane metadata.

### Terminal attach

`daemons attach DAEMON [--session NAME]` requires the ticket to advertise the `takeover_v1` terminal feature; if the Control Plane does not, attach refuses (exit 2) before connecting instead of guessing at the gateway's behaviour. Raw terminal mode is restored on every exit path, including a panic.

### SSH and local IDEs

Enable SSH with a locally held identity (only its adjacent `.pub` file is read):

```sh
daemons ssh enable DAEMON --identity ~/.ssh/id_ed25519 --wait
daemons ssh-config DAEMON --identity ~/.ssh/id_ed25519
daemons ide DAEMON --editor code
```

`ssh-config` writes private, managed OpenSSH files below `~/.ssh/daemons-run/` and adds one marked `Include` to `~/.ssh/config`; it never copies a private key or stores tickets. `daemons ssh keys list DAEMON` lists fingerprints, `ssh keys remove DAEMON FINGERPRINT` removes one key, and `ssh disable DAEMON` removes SSH access. `ide --cached` uses the saved config but every new SSH transport still mints a fresh ticket and needs a current login. The proxy sends only SSH bytes on stdout; diagnostics stay on stderr.

### Exit codes

`0` success; `1` API or operation failure; `2` usage or local validation; `3` authentication; `4` not found; `5` scope or capability denied; `6` web confirmation required; `7` rate or quota; `8` outcome unknown.
