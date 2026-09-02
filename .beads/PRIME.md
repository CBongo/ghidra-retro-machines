[bd prime] If this output is truncated by your host, read the full persisted hook output before
continuing. FIRST, THOUGH: run `bd memories` yourself. The memory INDEX is the part most likely
to be cut, and it is one cheap command to recover.

# Beads Workflow Context

> **Context Recovery**: Run `bd prime` after compaction, clear, or new session
> Hooks auto-call this in Claude Code and Codex when a beads workspace is resolved

## Persistent Memories — INDEX, NOT BODIES (bead grm-8ctl)

**The memory index is emitted immediately after this file, by `bd memories`, which the hook runs
as a second command.** Full bodies are NOT injected. To read one:

```bash
bd recall <key>          # the FULL body of one memory -- do this before acting on it
bd memories <search>     # the same index, filtered by keyword
```

**An index line is a hard TRUNCATION of the body's first line, not an authored summary. It can
stop mid-word. It is a pointer — do not act on it as though it were the whole memory.** Several
memories in this store exist specifically to stop a class of expensive mistake, and their first
line does not tell you which class. If a key looks relevant to what you are doing, `bd recall` it.

Write new knowledge with `bd remember`; do not create memory files.

<!--
WHY THIS FILE EXISTS. `.beads/PRIME.md` overrides `bd prime`'s output entirely (see
`bd prime --help`), which is how the memory bodies are suppressed. Everything below the marker is
bd 1.0.4's own default content, copied VERBATIM from `bd prime --export`; only the memories
section above was replaced.

Measured 2026-09-02: `bd prime` emitted 115,504 bytes, of which 110,823 were memory bodies. Hosts
truncate that to a ~2 KB preview and spill the rest to a file, so every memory after the first
alphabetically was silently absent from every session -- for Claude AND Codex, since both hooks
run the same command. With this override the pair emits ~10 KB.

THIS FILE IS AN INTERIM FIX AND SHOULD BE DELETED, NOT MAINTAINED. `bd prime --no-memories` was
merged upstream 2026-07-14 and ships in v1.1.2; this machine is on 1.0.4, where the flag does not
exist. Once `tools/upgrade-bd.ps1` has been run (it writes outside the repo, so it is the OWNER's
step -- see docs/human-research-todo.md), the correct configuration is:

    delete this file, and set both hooks to:  bd prime --no-memories && bd memories

That is strictly better than this file, and for one reason: everything below the marker is a
PINNED COPY of bd 1.0.4's own workflow text, so upstream improvements to it stop arriving. The
flag has no such cost. Do not invest in keeping this file current -- retire it.

If you must refresh it anyway (upgrade still pending, bd's text changed): run `bd prime --export`,
take everything from the SESSION CLOSE PROTOCOL heading onward, and replace the marked section
below. `--export` still includes the memory bodies (it ignores this file, not the memories), so do
not paste it in whole.
-->

<!-- ===== VERBATIM FROM bd 1.0.4 `bd prime --export` BELOW THIS LINE ===== -->

# 🚨 SESSION CLOSE PROTOCOL 🚨

**CRITICAL**: Before saying "done" or "complete", you MUST run this checklist:

```
[ ] 1. git status              (check what changed)
[ ] 2. git add <files>         (stage code changes)
[ ] 3. git commit -m "..."     (commit code)
[ ] 4. git push                (push to remote)
```

**NEVER skip this.** Work is not done until pushed.

## Core Rules
- **Default**: Use beads for ALL task tracking (`bd create`, `bd ready`, `bd close`)
- **Prohibited**: Do NOT use TodoWrite, TaskCreate, or markdown files for task tracking
- **Workflow**: Create beads issue BEFORE writing code, mark in_progress when starting
- **Memory**: Use `bd remember "insight"` for persistent knowledge across sessions. Do NOT use MEMORY.md files — they fragment across accounts. Search with `bd memories <keyword>`.
- Persistence you don't need beats lost context
- Git workflow: beads auto-commit to Dolt, run `git push` at session end
- Session management: check `bd ready` for available work

## Essential Commands

### Finding Work
- `bd ready` - Show issues ready to work (no blockers)
- `bd list --status=open` - All open issues
- `bd list --status=in_progress` - Your active work
- `bd show <id>` - Detailed issue view with dependencies

### Creating & Updating
- `bd create --title="Summary of this issue" --description="Why this issue exists and what needs to be done" --type=task|bug|feature --priority=2` - New issue
  - Priority: 0-4 or P0-P4 (0=critical, 2=medium, 4=backlog). NOT "high"/"medium"/"low"
- `bd update <id> --claim` - Claim work
- `bd update <id> --assignee=username` - Assign to someone
- `bd update <id> --title/--description/--notes/--design` - Update fields inline
- `bd close <id>` - Mark complete
- `bd close <id1> <id2> ...` - Close multiple issues at once (more efficient)
- `bd close <id> --reason="explanation"` - Close with reason
- **Tip**: When creating multiple issues/tasks/epics, use parallel subagents for efficiency
- **WARNING**: Do NOT use `bd edit` - it opens $EDITOR (vim/nano) which blocks agents

### Dependencies & Blocking
- `bd dep add <issue> <depends-on>` - Add dependency (issue depends on depends-on)
- `bd blocked` - Show all blocked issues
- `bd show <id>` - See what's blocking/blocked by this issue

### Sync & Collaboration
- `bd dolt push` - Push beads to Dolt remote
- `bd dolt pull` - Pull beads from Dolt remote
- `bd search <query>` - Search issues by keyword

### Project Health
- `bd stats` - Project statistics (open/closed/blocked counts)
- `bd doctor` - Check for issues (sync problems, missing hooks)
- `bd doctor --check=conventions` - Check for convention drift (lint, stale, orphans)

### Quality Tools
- `bd create --validate` - Check description has required sections
- `bd create --acceptance="criteria"` - Set acceptance criteria (checked by --validate)
- `bd create --design="decisions"` - Record design decisions
- `bd create --notes="context"` - Add supplementary notes
- `bd config set validation.on-create warn` - Auto-validate on every create
- `bd lint` - Check existing issues for missing sections

### Lifecycle & Hygiene
- `bd defer <id> --until="date"` - Defer work to a future date
- `bd supersede <id> --with=<new-id>` - Mark issue as superseded
- `bd close <id> --suggest-next` - Show newly unblocked issues after closing
- `bd stale` - Find issues with no recent activity
- `bd orphans` - Find issues with broken dependencies
- `bd preflight` - Pre-PR checks (lint, stale, orphans)
- `bd human <id>` - Flag for human decision (list/respond/dismiss)

### Structured Workflows
- `bd formula list` - See available workflow templates
- `bd mol pour <name>` - Start structured workflow from formula

## Common Workflows

**Starting work:**
```bash
bd ready           # Find available work
bd show <id>       # Review issue details
bd update <id> --claim  # Claim it
```

**Completing work:**
```bash
bd close <id1> <id2> ...    # Close all completed issues at once
git add . && git commit -m "..."  # Commit code changes
git push                    # Push to remote
```

**Creating dependent work:**
```bash
# Run bd create commands in parallel (use subagents for many items)
bd create --title="Implement feature X" --description="Why this issue exists and what needs to be done" --type=feature
bd create --title="Write tests for X" --description="Why this issue exists and what needs to be done" --type=task
bd dep add beads-yyy beads-xxx  # Tests depend on Feature (Feature blocks tests)
```
