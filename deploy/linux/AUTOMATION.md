# Linux integration automation

The normal developer path remains `deploy/linux/install-or-update.sh` followed by `deploy/linux/enroll.sh`.

Two bounded automation controls exist for the full-cycle acceptance harness:

- `NETA_SKIP_GIT_UPDATE=1` tells `install-or-update.sh` to build the exact Git ref already checked out instead of fetching/checking out/pulling `main`. The default is `0`, so normal manual behavior is unchanged.
- `NETA_ENROLLMENT_TOKEN` allows `enroll.sh` to run non-interactively. If no token is supplied and stdin is a TTY, the script keeps the existing hidden prompt. If stdin is non-interactive and no token is supplied, it fails instead of hanging.

The coordinator-owned full-cycle harness uses the `fleet enroll` CLI directly after the exact-ref install so the selected ref cannot be changed implicitly. It refuses refs whose installer predates `NETA_SKIP_GIT_UPDATE` support.

Enrollment tokens are process-scoped acceptance secrets. Do not put them in command history, source files, GitHub repository variables, workflow artifacts, or service environment files. The acceptance workflow generates a fresh token on the disposable coordinator host and destroys it with the test infrastructure.
