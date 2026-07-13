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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * A decrypt-on-the-fly loop recovered by {@link C64DecryptLoopAnalyzer}. This is the seam
 * between the two recovery tiers: the recognizer produces one of these regardless of key
 * model, and the tier is chosen from {@link #key()} --
 * a {@link KeyModel.Kind#CONSTANT} key is decrypted inline (a pure byte XOR), while a
 * rolling/computed key is handed to the {@link EmulationRecovery} harness with a
 * dirty-watch on {@link #target()}. Both paths converge on the same materialization
 * (a {@code DECRYPTED_xxxx} overlay + provenance), so the front end is shared.
 */
public class RecognizedDecryptor {

	/** How the loop derives the byte it XORs with. */
	public static final class KeyModel {
		/** Which key form the loop uses. */
		public enum Kind {
			/** {@code EOR #imm}: a single constant byte -- decryptable inline, no emulator. */
			CONSTANT,
			/** {@code EOR table,idx}: a rolling per-byte key read from memory -- needs emulation. */
			ROLLING,
			/** Key computed at runtime (chained, arithmetic) -- needs emulation. */
			COMPUTED,
			/** Transform present but not classifiable -- treat as suspect. */
			UNKNOWN;
		}

		private final Kind kind;
		private final int constant;      // valid iff kind == CONSTANT
		private final Address rollingBase; // valid iff kind == ROLLING

		private KeyModel(Kind kind, int constant, Address rollingBase) {
			this.kind = kind;
			this.constant = constant;
			this.rollingBase = rollingBase;
		}

		public static KeyModel constant(int keyByte) {
			return new KeyModel(Kind.CONSTANT, keyByte & 0xFF, null);
		}

		public static KeyModel rolling(Address base) {
			return new KeyModel(Kind.ROLLING, 0, base);
		}

		public static KeyModel of(Kind kind) {
			return new KeyModel(kind, 0, null);
		}

		public Kind kind() {
			return kind;
		}

		/** The constant key byte (only meaningful when {@link #kind()} is CONSTANT). */
		public int constant() {
			return constant;
		}

		/** The rolling key table base (only meaningful when {@link #kind()} is ROLLING). */
		public Address rollingBase() {
			return rollingBase;
		}

		@Override
		public String toString() {
			return switch (kind) {
				case CONSTANT -> String.format("CONSTANT($%02X)", constant);
				case ROLLING -> "ROLLING(" + rollingBase + ")";
				default -> kind.name();
			};
		}
	}

	/** How much to trust that this really is a decrypt loop. */
	public enum Confidence {
		/** A later {@code JMP}/{@code JSR} enters the rewritten range -- it is executed as
		 *  code, so recovery is applied automatically. */
		AUTO,
		/** Recognized by shape but nothing was seen to execute the range; recorded as a
		 *  candidate (bookmark only), never rewritten, to avoid mis-"decrypting" an ordinary
		 *  table transform. */
		CANDIDATE;
	}

	private final Address entry;
	private final AddressRange target;
	private final KeyModel key;
	private final Confidence confidence;
	private final Address jumpInto;

	/**
	 * @param entry      where recovery starts -- the loop's counter-init instruction (so an
	 *                   emulated run seeds the index register), falling back to the loop head
	 * @param target     the in-place range the loop rewrites, {@code [base, base+len)}
	 * @param key        the key model
	 * @param confidence AUTO if the range is executed as code, else CANDIDATE
	 * @param jumpInto   the branch instruction that enters {@code target}, or null
	 */
	public RecognizedDecryptor(Address entry, AddressRange target, KeyModel key,
			Confidence confidence, Address jumpInto) {
		this.entry = entry;
		this.target = target;
		this.key = key;
		this.confidence = confidence;
		this.jumpInto = jumpInto;
	}

	public Address entry() {
		return entry;
	}

	public AddressRange target() {
		return target;
	}

	public KeyModel key() {
		return key;
	}

	public Confidence confidence() {
		return confidence;
	}

	public Address jumpInto() {
		return jumpInto;
	}
}
