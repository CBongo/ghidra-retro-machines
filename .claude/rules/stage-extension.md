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
