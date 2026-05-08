# bioenv exec security notes

`bioenv exec -- COMMAND [ARGS...]` launches exactly one child process with the
current project's decrypted secrets merged into that child environment.

Security and lifecycle constraints:

- The parent shell environment is not modified.
- `bioenv` writes `KEY=VALUE` environment entries directly into temporary
  C-string buffers for the duration of `posix_spawnp`, instead of staging
  secret bytes in extra mutable byte arrays first.
- Those temporary buffers are explicitly zeroed before they are released,
  including error paths where process launch fails.
- Once spawned, the child process and any descendants can read the injected
  environment variables through normal process-environment APIs, so `exec`
  should be treated as a scoped secret handoff to that process tree.
