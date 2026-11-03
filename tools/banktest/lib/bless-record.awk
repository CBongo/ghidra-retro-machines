# The count movement between two realrom dumps, for the bless record (grm-c8mv, grm-kct6).
#
#   awk -f bless-record.awk <old dump> <new dump>
#
# Prints one line, "name old -> new" items joined by ", ", or nothing when no count moved.
#
# Every REALROM line is a count line unless it is a per-site listing (samples, call-width
# disagreements, exit-width sites, entries, blocks, bookmarks). A count line's numbers are its bare
# decimal tokens and the values of its key=<decimal> tokens; lines pair across the two dumps by
# their skeleton (numbers blanked) plus occurrence, so "dp operands=7272 known=916" pairs with
# "dp operands=7272 known=986" and reports "dp known 916 -> 986". Before grm-kct6 only
# "REALROM count <name> <n>" was read, and every analysis-row bless said "counts unchanged".
# A count line with no partner is "(new)" or "(gone)"; hash and name lines carry no numbers and
# never pair or report.

function listing() {
	return $2 ~ /^sample\./ || $2 ~ /\.truncated$/ || $2 == "calls.disagree" ||
		$2 == "entry" || $2 == "bookmark" || $2 == "block" || ($2 == "exitwidth" && $3 !~ /=/)
}

function scan(file,    i, t, skel, key, lead, k, nv, after) {
	if ($1 != "REALROM" || listing()) return
	skel = ""
	for (i = 2; i <= NF; i++) {
		t = $i
		if (t ~ /^[0-9]+$/) t = "#"
		else if (t ~ /=[0-9]+$/) sub(/=[0-9]+$/, "=#", t)
		skel = skel " " t
	}
	key = skel "@" (++seen[file, skel])
	lead = ""; nv = 0; after = 0
	for (i = 2; i <= NF; i++) {
		t = $i
		if (t ~ /^[0-9]+$/) { k = lead; v = t }
		else if (t ~ /=[0-9]+$/) {
			k = lead " " substr(t, 1, index(t, "=") - 1)
			v = substr(t, index(t, "=") + 1)
			after = 1
		}
		else { if (!after) lead = lead " " t; continue }
		sub(/^ /, "", k); sub(/^count /, "", k)
		name[key, ++nv] = k
		val[file, key, nv] = v   # kept as text: "008000" is an address, not 8000
	}
	if (!nv) return
	nvals[key] = nv
	has[file, key] = 1
	order[file, ++n[file]] = key
}

function add(s) { out = out sep s; sep = ", " }

FNR == NR { scan(1); next }
{ scan(2) }

END {
	for (i = 1; i <= n[2]; i++) {
		key = order[2, i]
		for (j = 1; j <= nvals[key]; j++) {
			if (!((1, key) in has)) add(name[key, j] " (new) " val[2, key, j])
			else if (val[1, key, j] != val[2, key, j])
				add(name[key, j] " " val[1, key, j] " -> " val[2, key, j])
		}
	}
	for (i = 1; i <= n[1]; i++) {
		key = order[1, i]
		if ((2, key) in has) continue
		for (j = 1; j <= nvals[key]; j++) add(name[key, j] " " val[1, key, j] " (gone)")
	}
	print out
}
