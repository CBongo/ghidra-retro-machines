/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retromachines;

import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.address.Address;

/**
 * Register values known to hold on entry to a specific address -- the caller-supplied
 * A/X/Y a backward scan may adopt instead of walking past {@code entryAddr}.
 * <p>
 * Exactly one thing populates a non-{@link #NONE} env: {@code HelperArgumentRecovery}'s
 * {@code callSiteRegisters}, at a bank-switch helper call site, with that helper's entry point
 * as {@code entryAddr}. {@link BankSwitchStrategy#depositHelperArgument} then hands it to a
 * strategy that re-evaluates the helper's own switch site under those registers -- grm-hum
 * increment 2's mini-inlining, which is how a helper taking its bank argument in a register
 * other than the one its mechanism write stores (Contra: argument in Y, {@code STA} of A) is
 * resolved without any input-register discovery. Every other path passes {@link #NONE}, for
 * which {@link #stopsAt} is always false and behavior is exactly as it was before.
 * <p>
 * <b>Soundness rule, recorded here because this record is what enables the exception.</b>
 * The backward scan normally refuses to attribute a value across a
 * control-flow join. The entry stop is an argued exception to that: at a function entry the
 * "other incoming paths" are other <em>call sites</em>, and an env-bearing query is asked on
 * behalf of one specific call site -- context-sensitive evaluation, not an ignored hazard.
 * What makes it safe is that <b>an env-derived result is only ever used for that one call
 * site's {@code CallEffect}</b> -- never written into {@code flow.switchResults()}, never into
 * {@code BoardBankAnalyzer}'s {@code matchCache}, never attributed to the switch site itself.
 * That is enforced structurally: {@link BankSwitchStrategy#computeSwitch} keeps its signature
 * and always passes {@link #NONE}, so nothing reachable from the cache can carry an env.
 * <p>
 * <b>{@code crossableJoin} extends that same argued exception one instruction further in</b>
 * (bead grm-k90). It is needed because for a PASS-THROUGH WRAPPER the entry stop is not
 * <em>reachable</em>: {@code entryAddr} is the wrapper's entry, the scan starts inside the
 * wrapped helper, and the wrapped helper's own entry sits between the two and is a genuine
 * control-flow join (the direct callers that bypass the wrapper). The join refusal fires there
 * and the walk dies before it can ever reach the stop. Contra, byte-exact:
 * <pre>
 *   c094  LDY #$01 / JSR $c139        &lt;- the call site whose Y we are asked about
 *   c139  LDA $8000                   &lt;- wrapper entry == entryAddr
 *   c13c  STA $07ec
 *   c13f  LDA $ffd0,Y                 &lt;- wrapped helper's entry: JSR'd directly from c0cb/c157/...
 *   c142  STA $ffd0,Y                 &lt;- the switch site the scan starts from
 * </pre>
 * Crossing {@code c13f} is correct <em>for this query</em> by exactly the argument the entry
 * stop already rests on. The query is context-sensitive to one call site, and on the path that
 * call took ({@code c094 -> c139 -> c13c -> c13f}) {@code c13c} genuinely IS {@code c13f}'s
 * immediate predecessor; the "other incoming paths" are again other call sites, which the env
 * answers for. What makes it safe rather than merely convenient is that whoever sets this field
 * has PROVED the span between {@code entryAddr} and it is straight-line, fully disassembled,
 * mechanism-inert and reached only by unconditional fallthrough -- that is
 * {@code HelperDiscovery.isPassThroughInto}'s admission test, the same proof that admitted
 * the wrapper model in the first place. And the structural guarantee above is unchanged and
 * still load-bearing: an env-derived result is used for one call site's {@code CallEffect}
 * only, never cached and never attributed to the switch site. That guarantee must not be
 * weakened, because it is what confines the exception to a context-sensitive query.
 * <p>
 * The field is deliberately ONE address, not a set: the shape that needs it is a single
 * wrapper-to-helper split, and a set would invite crossing joins whose predecessor edge nobody
 * proved. Chained pass-through wrappers still need only one, because the address that must be
 * crossed is the innermost helper's function entry -- every outer wrapper is contiguous with
 * the next and contributes no join of its own.
 * <p>
 * <b>{@code armPredecessors} is the PATH-FORKING generalization of that one licensed edge</b>
 * (bead grm-wul). Where {@code crossableJoin} licenses a walk to cross one join along its
 * PHYSICAL fall-through predecessor, an arm map names, per join, WHICH incoming edge the walk
 * takes: {@code join -> predecessor}, where the predecessor is the instruction (a branch, a jump,
 * or the fall-through) that flows into the join on the path this query is asked about. The walk
 * steps from the join straight to that predecessor, skipping the fall-through linkage test as
 * well as the join refusal -- a branch's target is not its fall-through -- and continues under
 * every other rule unchanged. It is the mechanism by which {@code BankDataflowEngine} evaluates
 * a switch site ONCE PER INCOMING ARM of the join heading its block, so that
 * {@code LDX #4 / BEQ m / LDX #6 / m: STX mechanism} resolves to {4, 6} rather than to unknown.
 * <p>
 * The same soundness discipline applies, in a slightly different form: an arm-derived value is
 * only ever a claim about THAT ARM, and the engine either uses every arm's value (a fork, one
 * element per arm) or none of them (a collapse). No single arm's value is ever attributed to the
 * site as if it held on every path. The map is empty for every env except the ones the engine's
 * arm enumeration builds.
 *
 * @param entryAddr     the address the scan stops at, or {@code null} for "never stop"
 * @param crossableJoin the one control-flow join a scan under this env may walk through, or
 *                      {@code null} (the default, and every env but a pass-through wrapper
 *                      call site's) for "cross nothing"
 * @param a             what A holds on entry
 * @param x             what X holds on entry
 * @param y             what Y holds on entry
 * @param armPredecessors per control-flow join, the predecessor instruction a walk under this env
 *                      steps to when it reaches that join (bead grm-wul); empty for "cross
 *                      nothing beyond {@code crossableJoin}"
 */
public record RegisterEnv(Address entryAddr, Address crossableJoin, BankState a, BankState x,
		BankState y, Map<Address, Address> armPredecessors) {

	/** The empty environment: no entry stop, no crossable join, nothing known. */
	public static final RegisterEnv NONE =
		new RegisterEnv(null, BankState.unknown(), BankState.unknown(), BankState.unknown());

	public RegisterEnv {
		armPredecessors = armPredecessors == null ? Map.of() : Map.copyOf(armPredecessors);
	}

	/** An env that crosses no join and knows nothing, but follows {@code arms} at each join it names. */
	public static RegisterEnv onArms(Map<Address, Address> arms) {
		return new RegisterEnv(null, null, BankState.unknown(), BankState.unknown(),
			BankState.unknown(), arms);
	}

	/** This env with {@code arms} as its arm map (replacing any it had). */
	public RegisterEnv withArms(Map<Address, Address> arms) {
		return new RegisterEnv(entryAddr, crossableJoin, a, x, y, arms);
	}

	/** Whether this env names any arm at all -- i.e. is a path-forking query. */
	public boolean hasArms() {
		return !armPredecessors.isEmpty();
	}

	/**
	 * The predecessor a walk reaching {@code join} steps to on this env's path, or {@code null}
	 * when this env says nothing about {@code join} (the walk then applies the ordinary linkage and
	 * join tests).
	 */
	public Address armPredecessorAt(Address join) {
		return armPredecessors.get(join);
	}

	/** {@code arms} as a deterministic (address-ordered) map, for rendering and for use as a key. */
	public static Map<Address, Address> sortedArms(Map<Address, Address> arms) {
		return new TreeMap<>(arms);
	}

	/**
	 * An env that stops at {@code entryAddr} knowing NOTHING about the caller's registers --
	 * the classification-only env {@link BankSwitchStrategy#classifyHelperBodyGap} scans under
	 * (bead grm-3ou part 1).
	 * <p>
	 * It is the degenerate case of the entry stop, and the degeneracy is the point: with every
	 * register unknown the stop cannot supply a value, so reaching it establishes exactly one
	 * fact -- that the backward walk got all the way to the helper's entry without finding a
	 * definition of the register, i.e. the register is LIVE at entry and the value is the
	 * caller's argument. A scan under this env must therefore never have its VALUE used; the
	 * soundness argument in this record's class javadoc still applies unchanged, and is if
	 * anything vacuous here, since there is nothing to attribute.
	 */
	public static RegisterEnv entryStopOnly(Address entryAddr) {
		return new RegisterEnv(entryAddr, BankState.unknown(), BankState.unknown(),
			BankState.unknown());
	}

	/**
	 * An env that crosses no join -- every env predating grm-k90, spelled the way it was
	 * spelled then. Kept as a convenience constructor rather than pushed onto callers because
	 * "cross nothing" is the correct and overwhelmingly common answer, and because a
	 * four-argument call site that reads {@code new RegisterEnv(entry, a, x, y)} cannot
	 * accidentally acquire a crossable join by a later edit to some other file.
	 */
	public RegisterEnv(Address entryAddr, BankState a, BankState x, BankState y) {
		this(entryAddr, null, a, x, y);
	}

	/** The pre-grm-wul five-argument form: no arm map. */
	public RegisterEnv(Address entryAddr, Address crossableJoin, BankState a, BankState x,
			BankState y) {
		this(entryAddr, crossableJoin, a, x, y, Map.of());
	}

	/** What {@code reg} ({@code 'A'}/{@code 'X'}/{@code 'Y'}) holds on entry; unknown otherwise. */
	public BankState get(char reg) {
		return switch (reg) {
			case 'A' -> a;
			case 'X' -> x;
			case 'Y' -> y;
			default -> BankState.unknown();
		};
	}

	/** Whether a backward scan reaching {@code addr} should stop and adopt this environment. */
	public boolean stopsAt(Address addr) {
		return entryAddr != null && entryAddr.equals(addr);
	}

	/**
	 * Whether a backward scan reaching {@code addr} may walk through it even though it is a
	 * control-flow join -- see this record's class javadoc for the soundness argument, which is
	 * the entry stop's argument applied one instruction further in.
	 * <p>
	 * Exact address equality, like {@link #stopsAt}, and for the same reason: the proof that
	 * licenses the crossing is about one specific instruction's one specific predecessor edge,
	 * so anything looser would be crossing joins nobody proved anything about. Every other
	 * guard the scan applies at that instruction -- fall-through linkage, the mechanism-write
	 * abort, the step bound -- is untouched and still runs.
	 */
	public boolean mayCrossJoinAt(Address addr) {
		return crossableJoin != null && crossableJoin.equals(addr);
	}
}
