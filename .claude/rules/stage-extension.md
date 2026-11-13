---
paths:
  - "build.gradle"
  - "tools/banktest/**"
---

# `stageExtensionForTests` and the runners that build by default (grm-4t2d)

`run-banktest.sh` and `realrom-test.sh` used to analyze with whatever was already staged in
`build/ghidra-home` — a stale-build result was possible and, worse, indistinguishable from a real
regression (see `AGENTS.md`'s "The runners build by default" section and the
`which-script-builds-the-extension` bd memory for the incident history). Both scripts now run
`gradle stageExtensionForTests` before analyzing, honouring an explicit opt-out:

```bash
bash tools/banktest/run-banktest.sh check --no-build nes-banking
GRM_SKIP_BUILD=1 bash tools/banktest/realrom-test.sh check nes
```

`stageExtensionForTests` (`build.gradle`) has real Gradle inputs (compiled classes, `data/`,
`ghidra_scripts/`, the packaging manifest) and outputs (the staged `Extensions/ghidra-retro-machines`
dir), so it is genuinely `UP-TO-DATE` when nothing relevant changed — the common case costs a few
seconds, not a rebuild. It deliberately does **not** key its up-to-date check on the dist zip
(`buildExtension`'s output): that Zip task's bytes are unstable across rebuilds (embedded
timestamps) even when the content is not, which is exactly the kind of perpetual-staleness bug
this task exists to avoid. It is named `stageExtensionForTests`, never `installExtension` — that
name is reserved, in spirit, for `tools/install-gui.ps1`, the real user-facing installer that
writes into the shared `%APPDATA%` Ghidra install and that agents must never run.

**Reader guard (grm-r324).** Every runner registers as a reader of the staged install for its
whole run (`grm_register_stage_reader` in `lib/common.sh`, called by `grm_preflight`: a file
`build/ghidra-home/.readers/<windows pid>`). The task **refuses** to re-stage a *changed*
extension while another live reader exists. Without that, a second gate started after a Java
edit would swap the classes under a running gate whose banner and cache key still name the old
build. The check is in the task's `doFirst`, which Gradle runs only when the task is out of
date, so two gates on an unchanged tree never block each other. If you hit the refusal, wait
for the other gate or use another worktree. Runner cleanup goes through `grm_on_exit`, never a
bare `trap ... EXIT`, which would drop the reader file's removal. A leftover file from a crashed
run is harmless: a dead or reused pid is treated as stale and deleted.
