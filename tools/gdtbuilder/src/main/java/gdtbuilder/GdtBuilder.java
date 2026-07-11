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
package gdtbuilder;

import java.io.File;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.GhidraApplicationLayout;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;

/**
 * Standalone build-time tool: reads the {@code types:} section of a machine descriptor
 * YAML (see docs/SCHEMA.md and machines/c64.yaml) and emits a Ghidra data-type file
 * archive ({@code .gdt}).
 * <p>
 * This class is NEVER shipped with the extension — it runs only as part of the Gradle
 * build (see the {@code gdtBuilder} source set / {@code buildGdt} task in build.gradle).
 * The runtime extension consumes only the resulting {@code .gdt} via the standard
 * Ghidra archive API; there is no YAML parser in the shipped extension.
 * <p>
 * Usage: {@code GdtBuilder <descriptor.yaml> <output.gdt>}
 */
public class GdtBuilder {

	public static void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.err.println("Usage: GdtBuilder <descriptor.yaml> <output.gdt>");
			System.exit(1);
		}
		File descriptorFile = new File(args[0]).getCanonicalFile();
		File outputGdt = new File(args[1]).getCanonicalFile();

		if (!Application.isInitialized()) {
			Application.initializeApplication(new GhidraApplicationLayout(),
				new HeadlessGhidraApplicationConfiguration());
		}

		// createFileArchive() throws DuplicateFileException if the .gdt (or its .ulock
		// sidecar) already exists, so clear both before every run.
		File lockFile = new File(outputGdt.getPath() + ".ulock");
		if (outputGdt.exists() && !outputGdt.delete()) {
			throw new IOException("Could not remove stale archive: " + outputGdt);
		}
		if (lockFile.exists() && !lockFile.delete()) {
			throw new IOException("Could not remove stale lock file: " + lockFile);
		}
		outputGdt.getParentFile().mkdirs();

		Map<String, Object> descriptor = YamlSupport.load(descriptorFile);
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> typeDefs = (List<Map<String, Object>>) descriptor.get("types");
		if (typeDefs == null) {
			typeDefs = new ArrayList<>();
		}

		FileDataTypeManager dtm = FileDataTypeManager.createFileArchive(outputGdt);
		int txId = dtm.startTransaction("build types from YAML");
		try {
			int count = buildTypes(dtm, typeDefs, descriptorFile.getParentFile());
			dtm.endTransaction(txId, true);
			dtm.save();
			System.err.println("Wrote " + count + " data type(s) to " + outputGdt
				+ " (" + outputGdt.length() + " bytes)");
		}
		catch (Exception e) {
			dtm.endTransaction(txId, false);
			throw e;
		}
		finally {
			dtm.close();
		}

		verifyArchive(outputGdt);
	}

	/**
	 * Sanity-check step: reopen the archive read-only via the same API the runtime
	 * extension will use, and log its path plus the count/names of every top-level
	 * data type to stderr.
	 */
	private static void verifyArchive(File outputGdt) throws IOException {
		FileDataTypeManager verify = FileDataTypeManager.openFileArchive(outputGdt, false);
		try {
			List<DataType> all = new ArrayList<>();
			verify.getAllDataTypes(all);
			System.err.println(
				"Verify: " + outputGdt.getAbsolutePath() + " contains " + all.size()
					+ " data type(s):");
			for (DataType dt : all) {
				if (dt instanceof Enum) {
					Enum e = (Enum) dt;
					System.err.println(
						"  " + dt.getName() + " (enum, " + e.getCount() + " member(s))");
				}
				else {
					System.err.println("  " + dt.getName());
				}
			}
			if (all.isEmpty()) {
				throw new IllegalStateException(
					"Reopened archive contains zero data types: " + outputGdt);
			}
		}
		finally {
			verify.close();
		}
	}

	/**
	 * Builds every entry in {@code typeDefs} into {@code dtm}, resolving `type:` field
	 * references (e.g. a struct field typed as another struct/enum in this archive) via
	 * a dependency-ordered (topological) pass so referenced types are always built first.
	 *
	 * @return number of top-level types created
	 */
	private static int buildTypes(FileDataTypeManager dtm, List<Map<String, Object>> typeDefs,
			File descriptorDir) throws IOException {
		Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
		Map<String, List<Map<String, Object>>> fieldsByName = new HashMap<>();
		Map<String, Integer> explicitSizeByName = new HashMap<>();
		for (Map<String, Object> typeDef : typeDefs) {
			String name = (String) typeDef.get("name");
			byName.put(name, typeDef);
			if ("struct".equals(typeDef.get("kind"))) {
				StructSource src = resolveFields(typeDef, descriptorDir);
				fieldsByName.put(name, src.fields);
				if (src.explicitSize != null) {
					explicitSizeByName.put(name, src.explicitSize);
				}
			}
		}

		List<String> order = topoSort(byName, fieldsByName);

		Map<String, DataType> built = new LinkedHashMap<>();
		for (String name : order) {
			Map<String, Object> typeDef = byName.get(name);
			String kind = (String) typeDef.get("kind");
			DataType dt;
			if ("flags".equals(kind)) {
				dt = buildFlags(typeDef);
			}
			else if ("enum".equals(kind)) {
				dt = buildEnum(typeDef, descriptorDir);
			}
			else if ("struct".equals(kind)) {
				dt = buildStruct(typeDef, fieldsByName.get(name), explicitSizeByName.get(name),
					built);
			}
			else {
				throw new IllegalArgumentException(
					"Unknown types[] kind '" + kind + "' for type '" + name + "'");
			}
			DataType resolved = dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			built.put(name, resolved);
		}
		return built.size();
	}

	/** Holds a struct's field list plus an optional explicit `size:` override. */
	private static final class StructSource {
		final List<Map<String, Object>> fields;
		final Integer explicitSize;

		StructSource(List<Map<String, Object>> fields, Integer explicitSize) {
			this.fields = fields;
			this.explicitSize = explicitSize;
		}
	}

	/**
	 * Returns the field list (and optional explicit `size:`) for a struct type, whether
	 * defined inline or via `source:`. A `size:` key on the type itself takes precedence;
	 * otherwise a `size:` key on the top level of a `source:` file is used. If neither is
	 * present, the struct length is later computed from the fields (max offset+size).
	 */
	@SuppressWarnings("unchecked")
	private static StructSource resolveFields(Map<String, Object> typeDef, File descriptorDir)
			throws IOException {
		if (typeDef.containsKey("fields")) {
			Integer explicitSize =
				typeDef.containsKey("size") ? intValue(typeDef.get("size")) : null;
			return new StructSource((List<Map<String, Object>>) typeDef.get("fields"),
				explicitSize);
		}
		String source = (String) typeDef.get("source");
		if (source == null) {
			throw new IllegalArgumentException(
				"struct '" + typeDef.get("name") + "' has neither fields: nor source:");
		}
		File sourceFile = new File(descriptorDir, source);
		if (!sourceFile.isFile()) {
			throw new IllegalArgumentException("struct '" + typeDef.get("name")
				+ "' references source file that does not exist: " + sourceFile);
		}
		Map<String, Object> sourceDoc = YamlSupport.load(sourceFile);
		List<Map<String, Object>> fields = (List<Map<String, Object>>) sourceDoc.get("fields");
		if (fields == null) {
			throw new IllegalArgumentException(
				"source file has no top-level 'fields:' list: " + sourceFile);
		}
		Integer explicitSize = typeDef.containsKey("size") ? intValue(typeDef.get("size"))
			: (sourceDoc.containsKey("size") ? intValue(sourceDoc.get("size")) : null);
		return new StructSource(fields, explicitSize);
	}

	/**
	 * Returns the value-entry list for an enum type, whether defined inline via
	 * {@code values:} or pulled from a shared {@code source:} file's {@code lists:} map (see
	 * {@link #buildEnum}). When {@code source:} is used, {@code lists:} on the type entry
	 * names one or more lists in that file to concatenate, in order — this is how a later
	 * dialect composes "shared base + my own extension range" without duplicating the base.
	 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> resolveEnumValues(Map<String, Object> typeDef,
			File descriptorDir) throws IOException {
		String name = (String) typeDef.get("name");
		if (typeDef.containsKey("values")) {
			return (List<Map<String, Object>>) typeDef.get("values");
		}
		String source = (String) typeDef.get("source");
		if (source == null) {
			throw new IllegalArgumentException(
				"enum '" + name + "' has neither values: nor source:");
		}
		File sourceFile = new File(descriptorDir, source);
		if (!sourceFile.isFile()) {
			throw new IllegalArgumentException("enum '" + name
				+ "' references source file that does not exist: " + sourceFile);
		}
		Map<String, Object> sourceDoc = YamlSupport.load(sourceFile);
		Map<String, List<Map<String, Object>>> lists =
			(Map<String, List<Map<String, Object>>>) sourceDoc.get("lists");
		if (lists == null) {
			throw new IllegalArgumentException(
				"source file has no top-level 'lists:' map: " + sourceFile);
		}
		List<Object> listNames = (List<Object>) typeDef.get("lists");
		if (listNames == null || listNames.isEmpty()) {
			throw new IllegalArgumentException(
				"enum '" + name + "' has source: but no lists: [...] naming which list(s) to use");
		}
		List<Map<String, Object>> combined = new ArrayList<>();
		for (Object listNameObj : listNames) {
			String listName = (String) listNameObj;
			List<Map<String, Object>> list = lists.get(listName);
			if (list == null) {
				throw new IllegalArgumentException("enum '" + name + "' references unknown list '"
					+ listName + "' in " + sourceFile);
			}
			combined.addAll(list);
		}
		return combined;
	}

	/**
	 * Orders type names so that any type referenced via a field's `type:` is built
	 * before the type that references it (Kahn's algorithm). Only struct kinds can have
	 * dependencies (a field naming another archive type); flags/enum kinds are leaves.
	 */
	private static List<String> topoSort(Map<String, Map<String, Object>> byName,
			Map<String, List<Map<String, Object>>> fieldsByName) {
		Map<String, Set<String>> deps = new LinkedHashMap<>();
		for (String name : byName.keySet()) {
			deps.put(name, new HashSet<>());
		}
		for (Map.Entry<String, List<Map<String, Object>>> entry : fieldsByName.entrySet()) {
			for (Map<String, Object> field : entry.getValue()) {
				String fieldType = (String) field.get("type");
				if (fieldType != null && byName.containsKey(fieldType)) {
					deps.get(entry.getKey()).add(fieldType);
				}
			}
		}

		List<String> order = new ArrayList<>();
		Set<String> visited = new HashSet<>();
		Deque<String> stack = new ArrayDeque<>();
		for (String name : byName.keySet()) {
			visitTopo(name, deps, visited, stack, order);
		}
		return order;
	}

	private static void visitTopo(String name, Map<String, Set<String>> deps, Set<String> visited,
			Deque<String> stack, List<String> order) {
		if (visited.contains(name)) {
			return;
		}
		if (stack.contains(name)) {
			throw new IllegalStateException("Cyclic type dependency involving '" + name + "'");
		}
		stack.push(name);
		for (String dep : deps.getOrDefault(name, Set.of())) {
			visitTopo(dep, deps, visited, stack, order);
		}
		stack.pop();
		visited.add(name);
		order.add(name);
	}

	private static EnumDataType buildFlags(Map<String, Object> typeDef) {
		String name = (String) typeDef.get("name");
		EnumDataType enumDt = new EnumDataType(name, 1);
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> bits = (List<Map<String, Object>>) typeDef.get("bits");
		if (bits != null) {
			for (Map<String, Object> bit : bits) {
				int bitNum = intValue(bit.get("bit"));
				String bitName = (String) bit.get("name");
				String comment = (String) bit.get("comment");
				long value = 1L << bitNum;
				if (comment != null) {
					enumDt.add(bitName, value, comment);
				}
				else {
					enumDt.add(bitName, value);
				}
			}
		}
		String comment = (String) typeDef.get("comment");
		if (comment != null) {
			enumDt.setDescription(comment);
		}
		return enumDt;
	}

	/**
	 * Builds a sequential-value enum: {@code values: [{value, name, comment}]}, either
	 * inline or (like struct's {@code source:}) pulled from an external YAML file so
	 * multiple archives/dialects can share one transcribed value list. Unlike {@code flags}
	 * (a bitmask enum whose value is derived from `bit:`), every entry here must carry an
	 * explicit `value:` — there is no implicit 0..N-1 assignment, since enums such as token
	 * tables commonly start at a nonzero base (e.g. 0x80). Duplicate names or duplicate
	 * values within one enum are rejected: {@link EnumDataType}'s underlying maps would
	 * otherwise silently overwrite/alias them rather than failing the build.
	 * <p>
	 * External sharing shape (see {@code machines/generated/basic-tokens.yaml}): the source
	 * file has a top-level {@code lists:} map of named value lists (e.g. a dialect's shared
	 * base range plus, later, per-dialect extension ranges that fork above the base). The
	 * type entry then names which lists to concatenate via {@code lists: [name, ...]}. This
	 * lets a later dialect (e.g. BASIC 4/7) add one new list to the shared file and one new
	 * `types:` entry (base list + its own extension list) without touching or re-transcribing
	 * the existing base list or any other machine's descriptor.
	 */
	private static EnumDataType buildEnum(Map<String, Object> typeDef, File descriptorDir)
			throws IOException {
		String name = (String) typeDef.get("name");
		int size = typeDef.containsKey("size") ? intValue(typeDef.get("size")) : 1;
		EnumDataType enumDt = new EnumDataType(name, size);
		List<Map<String, Object>> values = resolveEnumValues(typeDef, descriptorDir);
		if (values != null) {
			Set<String> seenNames = new HashSet<>();
			Set<Long> seenValues = new HashSet<>();
			for (Map<String, Object> entry : values) {
				String entryName = (String) entry.get("name");
				if (!entry.containsKey("value")) {
					throw new IllegalArgumentException("enum '" + name + "' entry '" + entryName
						+ "' has no explicit 'value:' (enum kind requires explicit values)");
				}
				long value = intValue(entry.get("value"));
				String comment = (String) entry.get("comment");
				if (!seenNames.add(entryName)) {
					throw new IllegalArgumentException(
						"enum '" + name + "' has duplicate member name '" + entryName + "'");
				}
				if (!seenValues.add(value)) {
					throw new IllegalArgumentException("enum '" + name + "' has duplicate value "
						+ value + " (member '" + entryName + "')");
				}
				if (comment != null) {
					enumDt.add(entryName, value, comment);
				}
				else {
					enumDt.add(entryName, value);
				}
			}
		}
		String comment = (String) typeDef.get("comment");
		if (comment != null) {
			enumDt.setDescription(comment);
		}
		return enumDt;
	}

	private static StructureDataType buildStruct(Map<String, Object> typeDef,
			List<Map<String, Object>> fields, Integer explicitSize, Map<String, DataType> built) {
		String name = (String) typeDef.get("name");

		int length;
		if (explicitSize != null) {
			length = explicitSize;
		}
		else {
			length = 0;
			for (Map<String, Object> field : fields) {
				int offset = intValue(field.get("offset"));
				int size = fieldSize(name, field, built);
				length = Math.max(length, offset + size);
			}
		}

		// Fixed length, prefilled with undefined bytes; replaceAtOffset() below overwrites
		// only the offsets we know about, leaving register-map gaps correctly undefined.
		StructureDataType struct = new StructureDataType(name, length);
		for (Map<String, Object> field : fields) {
			int offset = intValue(field.get("offset"));
			int size = fieldSize(name, field, built);
			String fieldName = (String) field.get("name");
			String comment = (String) field.get("comment");
			String fieldTypeName = (String) field.get("type");

			if (offset + size > length) {
				throw new IllegalArgumentException("Struct '" + name + "' field '" + fieldName
					+ "' at offset " + offset + " (size " + size
					+ ") exceeds struct length " + length);
			}

			DataType fieldType;
			if (fieldTypeName != null) {
				fieldType = built.get(fieldTypeName);
				if (fieldType == null) {
					throw new IllegalArgumentException("Struct '" + name + "' field '" + fieldName
						+ "' references unknown type '" + fieldTypeName + "'");
				}
			}
			else {
				fieldType = primitiveForSize(name, fieldName, size);
			}

			struct.replaceAtOffset(offset, fieldType, -1, fieldName, comment);
		}

		String comment = (String) typeDef.get("comment");
		if (comment != null) {
			struct.setDescription(comment);
		}
		return struct;
	}

	/** size=1 -> Byte, size=2 -> Word; anything else is not yet needed by any descriptor. */
	private static DataType primitiveForSize(String structName, String fieldName, int size) {
		switch (size) {
			case 1:
				return ByteDataType.dataType;
			case 2:
				return WordDataType.dataType;
			default:
				throw new IllegalArgumentException("Struct '" + structName + "' field '"
					+ fieldName + "' has unsupported untyped size " + size
					+ " (only 1 or 2 byte primitives are supported without an explicit 'type:')");
		}
	}

	private static int fieldSize(String structName, Map<String, Object> field,
			Map<String, DataType> built) {
		String fieldTypeName = (String) field.get("type");
		if (fieldTypeName != null) {
			DataType dt = built.get(fieldTypeName);
			if (dt != null) {
				return dt.getLength();
			}
		}
		Object sizeObj = field.get("size");
		if (sizeObj == null) {
			throw new IllegalArgumentException("Struct '" + structName + "' field '"
				+ field.get("name") + "' has neither 'size:' nor a resolvable 'type:'");
		}
		return intValue(sizeObj);
	}

	private static int intValue(Object o) {
		if (o instanceof Number) {
			return ((Number) o).intValue();
		}
		throw new IllegalArgumentException("Expected numeric value, got: " + o);
	}
}
