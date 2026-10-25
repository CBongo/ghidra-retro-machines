# grm-jdtls

This repo's replacement for the official `jdtls-lsp` plugin (bead `grm-jwt6`). The server is the
same `jdtls` on PATH; the config lives in `../../.claude-plugin/marketplace.json`, and the
project's `.claude/settings.json` declares the marketplace, enables this plugin, and turns
`jdtls-lsp` off for this repo only (your other Java projects keep the official one).

Why it exists: after the 12.2 retarget the official plugin kept reporting 12.1-era API errors
("method newBoolean(String) is undefined", "SYMBOL_CACHE cannot be resolved") on every edit.

| Cause | Fix |
|---|---|
| jdtls' default `updateBuildConfiguration` is `interactive`: it asks the client before re-syncing a changed Gradle build, and Claude Code never answers, so the classpath is never refreshed | `automatic`, via `initializationOptions` and `settings` |
| jdtls runs Gradle with the session's environment, so a version-pinned `GHIDRA_INSTALL_DIR` from session start overrides `ghidraInstallRoot` + `ghidraTargetVersion` (see CLAUDE.md) | `env` blanks it; an empty value falls through, exactly as `GHIDRA_INSTALL_DIR= gradle …` does |
| Leftover `.claude/worktrees/*` dirs were imported as phantom projects that fail every sync | `.claude/**` is excluded from import |

The workspace stays jdtls' default (`%APPDATA%/jdtls/jdtls-<sha1 of the folder name>` on Windows).
It cannot live inside the repo: Eclipse rejects a workspace nested in the project it imports
("Invalid project description").

## Setup (once per machine)

The first session in this repo offers to trust the `grm-local` marketplace; accept it. Or, from
any shell, mid-session:

```bash
claude plugin marketplace add ./.claude/marketplace     # user scope; do NOT use --scope project,
claude plugin install grm-jdtls@grm-local --scope project  # it rewrites the committed path absolute
```

then `/reload-plugins`.

## Diagnostics look stale anyway?

Mid-session, no restart: `/reload-plugins` stops jdtls; while it is down, delete its workspace
dir (above) and `bin/`; `/reload-plugins` again and make any edit. The next start is a fresh
import (a minute or two). Never delete the workspace while jdtls is running.

The `tools/banktest/*.java` "not on the classpath" warnings are expected: those are Ghidra
scripts, not project sources.
