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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;

/**
 * Descriptor-selected BASIC token lookup backed by enum types in a machine GDT archive.
 * The primary enum covers ordinary one-byte tokens; configured prefix enums cover dialects
 * such as BASIC 7, whose {@code $CE}/{@code $FE} bytes dispatch through one following byte.
 */
final class BasicDescriptorTokenLookup implements BasicTokenLookup {

	/** One two-byte-token dispatch page declared by {@code formats.prg.basic.prefix_enums}. */
	record PrefixDefinition(int prefix, String enumName) {
	}

	private final ghidra.program.model.data.Enum tokenEnum;
	/* A present key with a null value means its configured archive enum was unavailable. */
	private final Map<Integer, ghidra.program.model.data.Enum> prefixEnums;
	private final List<String> missingPrefixEnums;

	private BasicDescriptorTokenLookup(ghidra.program.model.data.Enum tokenEnum,
			Map<Integer, ghidra.program.model.data.Enum> prefixEnums, List<String> missingPrefixEnums) {
		this.tokenEnum = tokenEnum;
		this.prefixEnums = Collections.unmodifiableMap(new LinkedHashMap<>(prefixEnums));
		this.missingPrefixEnums = List.copyOf(missingPrefixEnums);
	}

	/**
	 * Opens a lookup from an already-open descriptor archive. Returns {@code null} when the
	 * primary enum is absent. A missing configured prefix enum is retained as an unavailable
	 * page so its bytes remain losslessly raw rather than being misread as primary tokens.
	 */
	static BasicDescriptorTokenLookup fromGdt(FileDataTypeManager gdtMgr, String tokenEnumName,
			List<PrefixDefinition> prefixes) {
		if (gdtMgr == null || tokenEnumName == null) {
			return null;
		}
		ghidra.program.model.data.Enum primary = findEnum(gdtMgr, tokenEnumName);
		if (primary == null) {
			return null;
		}
		Map<Integer, ghidra.program.model.data.Enum> pages = new LinkedHashMap<>();
		List<String> missing = new java.util.ArrayList<>();
		for (PrefixDefinition prefix : prefixes) {
			ghidra.program.model.data.Enum page = findEnum(gdtMgr, prefix.enumName());
			pages.put(prefix.prefix(), page);
			if (page == null) {
				missing.add(prefix.enumName());
			}
		}
		return new BasicDescriptorTokenLookup(primary, pages, missing);
	}

	/** Configured prefix enum names that were not available in the descriptor's GDT. */
	List<String> missingPrefixEnums() {
		return missingPrefixEnums;
	}

	private static ghidra.program.model.data.Enum findEnum(FileDataTypeManager gdtMgr,
			String enumName) {
		DataType dt = gdtMgr.getDataType(CategoryPath.ROOT, enumName);
		return dt instanceof ghidra.program.model.data.Enum e ? e : null;
	}

	@Override
	public Match lookup(byte[] data, int offset) {
		if (offset < 0 || offset >= data.length) {
			return null;
		}
		int first = data[offset] & 0xff;
		if (first < 0x80) {
			return null;
		}

		// A configured prefix always owns its first byte. A complete but unrecognized pair is
		// returned as a two-byte raw match, so its selector cannot affect later quote or DATA
		// state. A truncated prefix remains one raw byte.
		if (prefixEnums.containsKey(first)) {
			if (offset + 1 >= data.length) {
				return null;
			}
			ghidra.program.model.data.Enum page = prefixEnums.get(first);
			String name = page == null ? null : enumMember(page, data[offset + 1] & 0xff);
			return new Match(2, name);
		}

		String name = enumMember(tokenEnum, first);
		return name == null ? null : new Match(1, name);
	}

	private static String enumMember(ghidra.program.model.data.Enum tokenEnum, int value) {
		try {
			return tokenEnum.getName(value);
		}
		catch (Exception e) {
			return null;
		}
	}
}
