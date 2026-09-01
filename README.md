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

4. On macOS, Gatekeeper can block this temporary unsigned, unnotarized beta because downloaded files receive the `com.apple.quarantine` attribute. After the checksum succeeds, remove that attribute from the installed binary:

   ```sh
   xattr -d com.apple.quarantine "$HOME/.local/bin/daemons"
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
| `daemons servers list` / `servers show ID` | `GET /api/v1/servers[/{server}]` | `servers:read` |
| `daemons list` (alias `ls`) / `show ID` | `GET /api/v1/daemons[/{daemon}]` | `daemons:read` |
| `daemons operations list [--limit N]` | `GET /api/v1/operations?limit=N` (1 to 200) | `operations:read` |
| `daemons operations show ID` | `GET /api/v1/operations/{operation}` | `operations:read` |

`daemons show ID` prints the daemon's current `ETag`; `daemons destroy` uses that value for its conditional delete.

### Mutations

Every mutation takes `--idempotency-key KEY` (8 to 128 characters of letters, digits, `.`, `_`, `:`, `-`). Interactively the CLI generates one, prints it on stderr before submitting, and reuses it for the whole command. With `--json` or without a terminal an explicit key is required, so a script can never retry under a fresh key by accident. Every mutation also performs the API version preflight (`GET /api/v1`, scope `control-plane:discover`).

| Command | API route | Scope |
| --- | --- | --- |
| `daemons spawn NAME --server SERVER [--agent AGENT] [--disk-quota-gb N]` | `POST /api/v1/daemons` | `daemons:write` (plus `servers:read` when `--server` is a name) |
| `daemons start\|stop\|restart\|retry ID` | `POST /api/v1/daemons/{daemon}/{action}` | `daemons:write` |
| `daemons destroy ID [--etag ETAG]` | `GET /api/v1/daemons/{daemon}` then `DELETE /api/v1/daemons/{daemon}` with `If-Match` | `daemons:read`, `daemons:destroy` |

`--server` accepts the server UUID or its exact name (no prefix matching). `daemons spawn` prints the new daemon and its `daemon.spawn` operation; in `--json` mode stdout is the API's 202 document with the operation under `meta.operation`.

`daemons destroy` reads the daemon first to capture its `ETag` and sends it as `If-Match`, so a daemon that changed in between is never destroyed blindly. Pass `--etag` to pin a value you captured yourself and skip the read. On `412 precondition_failed` the CLI re-reads the daemon, shows its current state and new ETag, and exits 1 without resubmitting.

### Waiting for operations

Add `--wait` to any mutation to poll its operation until it reaches a terminal state (`succeeded`, `failed`, `partially_succeeded`, `cancelled`, `timed_out`, or `outcome_unknown`). Polling honours `Retry-After`, otherwise backs off from 2s to 15s with jitter. `--wait-timeout` bounds the wait (default `10m`). Ctrl-C stops waiting locally; it never cancels the operation on the server.

In `--json` mode with `--wait`, stdout carries the mutation's document first and, once polling ends, the final operation document on its own line. Progress lines go to stderr and are suppressed by `--quiet`.

Outcomes: `partially_succeeded` is reported as a failure (exit 1) with the operation's `result` printed so you can see what landed. A wait that hits its timeout exits 8 with the last known state and the `daemons operations show ID` command to check it.

### Confirmation and unknown outcomes

When the API answers `409 confirmation_required` (for example on `daemons destroy`), nothing has changed. The CLI prints the safe summary, the approval URL, the expiry and the confirmation ID, and exits 6. In an interactive terminal it offers to open the approval URL in your browser; opening it is never treated as consent, and the CLI never polls or approves on your behalf. Approve in the browser, then run the same command again. With `--json` the canonical problem document is written to stdout and no browser is opened.

When a mutation's outcome cannot be determined (a transport failure after dispatch, an invalid response, or an operation ending in `outcome_unknown`), the CLI exits 8 and prints the reconciliation step to run first (for example `daemons list` after a spawn, `daemons show ID` after a lifecycle action) and the exact replay command with the original idempotency key. It never retries a possibly destructive or billable mutation on its own, and never under a new key.

### Exit codes

`0` success; `1` API or operation failure; `2` usage or local validation; `3` authentication; `4` not found; `5` scope or capability denied; `6` web confirmation required; `7` rate or quota; `8` outcome unknown.
