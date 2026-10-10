---
paths:
  - "tools/install-gui.ps1"
---

# GUI install (`tools/install-gui.ps1`)

The GUI install (delete+unzip the dist zip into `%APPDATA%/ghidra/<version>/Extensions/`) is a
separate, user-facing step — only needed when you want the interactive Ghidra GUI to see the
new build; it is **not** part of the agent test loop, so the GUI keeps running whatever build
was last installed there until you refresh it. Run it yourself with:

```powershell
.\tools\install-gui.ps1              # gradle buildExtension, then destructive reinstall
.\tools\install-gui.ps1 -SkipBuild   # install the newest dist zip as-is
.\tools\install-gui.ps1 -WhatIf      # resolve and report paths, install nothing
```

It refuses to run while Ghidra is open (a live install holds locks on its own jars; `-Force`
overrides) and always reinstalls rather than skipping — you invoke it when you want a fresh
copy. Restart Ghidra afterwards. Agents should not run it: it writes outside the repo, into
the user's shared `%APPDATA%` install.
