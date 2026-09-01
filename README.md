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
