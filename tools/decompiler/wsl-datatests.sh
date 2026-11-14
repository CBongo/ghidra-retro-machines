#!/bin/bash
# Build decomp_test_dbg from a Ghidra checkout and run the decompiler datatests + unittests.
# RUNS INSIDE WSL (AGENTS.md: POSIX-only native work), never in git bash. Invoke from git bash as
#   wsl -e bash -lc 'SLEIGHPATH=/mnt/<drive>/<ghidra install> bash /mnt/<...>/wsl-datatests.sh <arm> <checkout> [base-arm]'
#
#   <arm>       name of this build; work dir is ~/prtest/<arm>, logs ~/prtest/<arm>-{build,datatests,unit}.log
#   <checkout>  a Ghidra source tree (WSL path, e.g. /mnt/d/git/ghidra-pr-x); only its
#               Ghidra/Features/Decompiler/src/decompile subtree is COPIED into the WSL home and built
#               there (9P under /mnt is slow, and git must never run from WSL on a Windows checkout)
#   [base-arm]  start from a copy of an earlier arm's build and replace only the .cc/.hh files that
#               differ, so a one-file PR branch rebuilds incrementally against its control
#   SLEIGHPATH  (required) a Ghidra install or build whose .sla files the datatests load. A release
#               install has no Toy language: skipnext2.xml and ~22 unittests fail on every arm
#               (environmental). Compare arms against a control arm, not against zero failures.
#
# Written for grm-hf5h.1/.2 and grm-gipk.25 (per-branch PR verification, 2026-11-14); method from
# the ghidra-12-1-3-native-regression-gp6936 bd memory (CRLF stripped, generated parsers touched).
set -u
ARM=${1:?arm name}; WT=${2:?checkout dir}; BASE=${3:-}
: "${SLEIGHPATH:?set SLEIGHPATH to a Ghidra install (WSL path)}"
SRC=$WT/Ghidra/Features/Decompiler/src/decompile
DST=$HOME/prtest/$ARM
rm -rf "$DST"; mkdir -p "$HOME/prtest"
if [ -n "$BASE" ]; then
	cp -a "$HOME/prtest/$BASE" "$DST"
	for f in "$SRC"/cpp/*.cc "$SRC"/cpp/*.hh; do
		b=$(basename "$f")
		if ! sed 's/\r$//' "$f" | cmp -s - "$DST/cpp/$b"; then
			echo "replacing $b"; sed 's/\r$//' "$f" > "$DST/cpp/$b"
		fi
	done
else
	cp -r "$SRC" "$DST"
	find "$DST" \( -name '*.cc' -o -name '*.hh' -o -name Makefile -o -name '*.xml' -o -name '*.h' -o -name '*.y' -o -name '*.l' \) -exec sed -i 's/\r$//' {} +
	# Committed generated parsers must look newer than their .y/.l, or make tries to regenerate them.
	sleep 1; touch "$DST"/cpp/*.cc "$DST"/cpp/*.hh; sleep 1
	touch "$DST"/cpp/xml.cc "$DST"/cpp/grammar.cc "$DST"/cpp/slghparse.cc "$DST"/cpp/slghscan.cc "$DST"/cpp/pcodeparse.cc
fi
cd "$DST/cpp" || exit 1
make -j4 decomp_test_dbg > "$HOME/prtest/$ARM-build.log" 2>&1
echo "build rc=$?"; [ -x decomp_test_dbg ] || { echo "no decomp_test_dbg; see $HOME/prtest/$ARM-build.log"; exit 1; }
./decomp_test_dbg -sleighpath "$SLEIGHPATH" datatests > "$HOME/prtest/$ARM-datatests.log" 2>&1
grep "Total passing" "$HOME/prtest/$ARM-datatests.log"
./decomp_test_dbg -sleighpath "$SLEIGHPATH" unittests > "$HOME/prtest/$ARM-unit.log" 2>&1
grep "tests passed" "$HOME/prtest/$ARM-unit.log"
