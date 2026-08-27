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

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.util.DefaultLanguageService;

/**
 * Descriptor/archive resource loading, split out of {@link DescriptorSupport} (QR-12
 * increment 5): bundled compiled descriptors and data-type archives, and the language-id
 * resolution that goes with them.
 */
final class DescriptorResources {

	private DescriptorResources() {
	}

	// ------------------------------------------------------------------
	// Descriptor / archive loading
	// ------------------------------------------------------------------

	/** Loads a bundled compiled descriptor, e.g. {@code machines/c64.map}. */
	static JsonObject loadMap(String mapPath) throws IOException {
		ResourceFile mapFile = Application.findDataFileInAnyModule(mapPath);
		if (mapFile == null) {
			throw new IOException("Could not find bundled data file " + mapPath);
		}
		try (InputStreamReader reader =
				new InputStreamReader(mapFile.getInputStream(), StandardCharsets.UTF_8)) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	/**
	 * Resolves the processor language a descriptor should load with: the compiled map's
	 * {@code system.language} when that language is actually available to Ghidra (bundled
	 * or installed), otherwise {@code safetyFallbackId}. This is how a loader "stops
	 * passing a fallback language" once the descriptor's real language is bundled (bead
	 * grm-bk6): the descriptor names {@code 6510:LE:16:default}, the extension ships it,
	 * and this returns it; the hard-coded 6502 fallback only fires in a broken install
	 * where even the descriptor's language is missing.
	 */
	static String resolveLanguageId(JsonObject map, String safetyFallbackId) {
		JsonObject system = map.getAsJsonObject("system");
		String declared =
			system != null && system.has("language") ? system.get("language").getAsString() : null;
		if (declared != null && languageAvailable(declared)) {
			return declared;
		}
		return safetyFallbackId;
	}

	/** Variant field of the language IDs that decode the undocumented NMOS opcodes. */
	private static final String UNDOC_VARIANT = "undoc";

	/**
	 * The undocumented-opcode sibling of {@code languageId} -- e.g.
	 * {@code 6510:LE:16:default} to {@code 6510:LE:16:undoc} (bead grm-azg) -- or
	 * {@code null} when this build ships no such variant. A Ghidra language ID is
	 * {@code processor:endian:size:variant}, so the sibling differs only in the last field.
	 * <p>
	 * Loaders use this to OFFER the variant as an additional, non-preferred
	 * {@link ghidra.app.util.opinion.LoadSpec}, so returning {@code null} for anything
	 * unrecognized or unavailable is the point: a missing variant must quietly mean "don't
	 * offer it", never an exception on an import path.
	 */
	static String undocVariantOf(String languageId) {
		if (languageId == null) {
			return null;
		}
		int lastColon = languageId.lastIndexOf(':');
		if (lastColon < 0) {
			return null;
		}
		String sibling = languageId.substring(0, lastColon + 1) + UNDOC_VARIANT;
		if (sibling.equals(languageId) || !languageAvailable(sibling)) {
			return null;
		}
		return sibling;
	}

	private static boolean languageAvailable(String id) {
		try {
			DefaultLanguageService.getLanguageService()
					.getLanguageDescription(new LanguageID(id));
			return true;
		}
		catch (LanguageNotFoundException e) {
			return false;
		}
	}

	/** Opens a bundled data-type archive, e.g. {@code machines/c64.gdt}. */
	static FileDataTypeManager openGdt(String gdtPath) throws IOException {
		ResourceFile gdtFile = Application.findDataFileInAnyModule(gdtPath);
		if (gdtFile == null) {
			throw new IOException("Could not find bundled data file " + gdtPath);
		}
		return FileDataTypeManager.openFileArchive(gdtFile, false);
	}
}
