// Narrow probe (grm-gipk.34): every EOL comment matching a regex, with its address, owning function
// and the number of computed references leaving that instruction. Answers "which sites did analyzer
// X annotate in this row" without knowing the sites in advance -- e.g. GRM_EOL_MATCH='split dispatch'
// lists every SplitDispatchTableAnalyzer site, stub form (comment on the JSR) and inline form (on the
// JMP (P)) alike, which SwitchLabelCensus cannot (it only sees computed jumps). Read-only.
//
//   GRM_EOL_MATCH='<java regex>' REALROM_EXTRA_POSTSCRIPT=EolCommentProbe.java \
//     REALROM_WORK_DIR=<dir> bash tools/banktest/realrom-test.sh check <set> [--only <ids>]
//
// One line per match:  EOL <program> <space::addr> fn=<name|-> computed=<n> | <comment, one line>
// then "EOL-SUM <program> matches=<n>". Unset GRM_EOL_MATCH prints nothing but the summary.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import java.util.regex.Pattern;

public class EolCommentProbe extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String prog = currentProgram.getName().replace(' ', '_');
		String re = System.getenv("GRM_EOL_MATCH");
		int n = 0;
		if (re != null && !re.isBlank()) {
			Pattern p = Pattern.compile(re);
			Listing listing = currentProgram.getListing();
			AddressIterator it = listing.getCommentAddressIterator(CommentType.EOL,
				currentProgram.getMemory(), true);
			while (it.hasNext()) {
				Address a = it.next();
				String c = listing.getComment(CommentType.EOL, a);
				if (c == null || !p.matcher(c).find()) {
					continue;
				}
				n++;
				Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
				int computed = 0;
				for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(a)) {
					if (r.getReferenceType().isComputed()) {
						computed++;
					}
				}
				println("EOL " + prog + " " + a.getAddressSpace().getName() + "::" +
					Long.toHexString(a.getOffset()) + " fn=" + (f == null ? "-" : f.getName()) +
					" computed=" + computed + " | " + c.replace('\n', ' ').replace('\r', ' '));
			}
		}
		println("EOL-SUM " + prog + " matches=" + n);
	}
}
