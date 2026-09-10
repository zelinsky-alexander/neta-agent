# Linux integration automation

The normal developer/source-build path remains `deploy/linux/install-or-update.sh` followed by `deploy/linux/enroll.sh`.

For cloud acceptance and production-like fresh-host validation, prefer the immutable package path:

```bash
sudo ./deploy/linux/install-package.sh neta-agent-linux-amd64-<commit>.tar.gz
```

`install-package.sh` does **not** run Git, CMake, a compiler, or the C++ test suite. It validates the package architecture, installs only Linux runtime dependencies, installs the versioned `neta-agent`, updater and optional TLS context library, creates the systemd service/environment when absent, and starts the service.

The `Build Supported Agent Flavors` workflow publishes immutable Linux development releases tagged `dev-<full-commit-sha>` with AMD64 and ARM64 packages plus `release-manifest.json`. The full-cycle acceptance harness resolves the requested agent ref to its exact commit, downloads the package matching the endpoint architecture, verifies the manifest SHA-256, and then performs a runtime-only install.

If a selected commit does not yet have a published development package, build/publish that ref first rather than compiling it on the acceptance endpoint.

Two additional bounded automation controls remain available for developer/source-build flows:

- `NETA_SKIP_GIT_UPDATE=1` tells `install-or-update.sh` to build the exact Git ref already checked out instead of fetching/checking out/pulling `main`. The default is `0`, so normal manual behavior is unchanged.
- `NETA_ENROLLMENT_TOKEN` allows `enroll.sh` to run non-interactively. If no token is supplied and stdin is a TTY, the script keeps the existing hidden prompt. If stdin is non-interactive and no token is supplied, it fails instead of hanging.

Enrollment tokens are process-scoped acceptance secrets. Do not put them in command history, source files, GitHub repository variables, workflow artifacts, or service environment files. The acceptance workflow generates a fresh token on the disposable coordinator host and destroys it with the test infrastructure.
