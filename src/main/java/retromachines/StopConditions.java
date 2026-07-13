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

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

/**
 * Bounds for an {@link EmulationRecovery} run. Every run is bounded on all axes so a
 * runaway or non-terminating emulated routine can never hang the analysis: an instruction
 * budget and a wall-clock budget always apply, and a run additionally stops early when it
 * reaches a caller-supplied exit address ({@link #exitAddresses()}) or when a watched
 * target range becomes fully written ({@link #dirtyWatch()} -- the natural completion for
 * a decrypt loop or block copy whose output range is known in advance).
 *
 * <p>Instances are immutable; build with {@link #builder()}.
 */
public final class StopConditions {

	/** Default instruction budget: ample for KB-scale 8-bit loops, cheap to exhaust safely. */
	public static final long DEFAULT_FUEL = 1_000_000L;
	/** Default wall-clock budget in milliseconds. */
	public static final long DEFAULT_WALLCLOCK_MILLIS = 5_000L;

	private final long instructionFuel;
	private final long wallClockMillis;
	private final AddressSetView exitAddresses;
	private final AddressSetView dirtyWatch;

	private StopConditions(Builder b) {
		this.instructionFuel = b.instructionFuel;
		this.wallClockMillis = b.wallClockMillis;
		this.exitAddresses = b.exitAddresses;
		this.dirtyWatch = b.dirtyWatch;
	}

	/** Maximum instructions to step before stopping with {@link StopReason#FUEL}. */
	public long instructionFuel() {
		return instructionFuel;
	}

	/** Maximum wall-clock milliseconds before stopping with {@link StopReason#WALLCLOCK}. */
	public long wallClockMillis() {
		return wallClockMillis;
	}

	/** Addresses that, when reached as the program counter, stop the run with
	 *  {@link StopReason#EXIT_RANGE}. Never null; empty means "no exit address". */
	public AddressSetView exitAddresses() {
		return exitAddresses;
	}

	/** Target range whose full coverage by writes stops the run with
	 *  {@link StopReason#DIRTY_WATCH}. Null means "do not watch". */
	public AddressSetView dirtyWatch() {
		return dirtyWatch;
	}

	/** A new builder seeded with the default fuel and wall-clock budgets and no
	 *  exit/dirty-watch conditions. */
	public static Builder builder() {
		return new Builder();
	}

	/** Fluent builder for {@link StopConditions}. */
	public static final class Builder {
		private long instructionFuel = DEFAULT_FUEL;
		private long wallClockMillis = DEFAULT_WALLCLOCK_MILLIS;
		private AddressSetView exitAddresses = new AddressSet();
		private AddressSetView dirtyWatch = null;

		private Builder() {}

		/** Set the instruction budget (values &lt;= 0 fall back to {@link #DEFAULT_FUEL}). */
		public Builder instructionFuel(long fuel) {
			this.instructionFuel = fuel > 0 ? fuel : DEFAULT_FUEL;
			return this;
		}

		/** Set the wall-clock budget in ms (values &lt;= 0 fall back to the default). */
		public Builder wallClockMillis(long millis) {
			this.wallClockMillis = millis > 0 ? millis : DEFAULT_WALLCLOCK_MILLIS;
			return this;
		}

		/** Stop when the program counter reaches any address in {@code exits}. */
		public Builder exitAddresses(AddressSetView exits) {
			this.exitAddresses = exits != null ? exits : new AddressSet();
			return this;
		}

		/** Stop once every address in {@code target} has been written. */
		public Builder dirtyWatch(AddressSetView target) {
			this.dirtyWatch = target;
			return this;
		}

		/** Build the immutable {@link StopConditions}. */
		public StopConditions build() {
			return new StopConditions(this);
		}
	}
}
