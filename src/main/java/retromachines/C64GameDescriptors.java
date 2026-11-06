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

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import gdtbuilder.GameCompiler;
import generic.jar.ResourceFile;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Per-game descriptors for C64 programs (bead {@code grm-hb6.30}; schema in
 * docs/per-game-descriptors-design.md section 3.8): the C64 counterpart of
 * {@link GameDescriptorRegistry}, reading the SAME two sources (curated {@code games/*.gmap},
 * and the user overlay {@code <settings>/retro-machines/games/*.yaml}, overlay first) but
 * matching a different identity.
 * <p>
 * <b>Identity is the MEMBER's own content sha256</b> -- the whole {@code .prg} byte string, load
 * address included -- not a container path. A program therefore resolves identically loose or as
 * a member of a {@code .d64}/{@code .g64} (the filesystem plugin hands the loader the member's
 * bytes), and renaming or re-imaging a disk changes nothing. A descriptor lists the members of
 * one game; game-level sections apply to every member, member-level ones to that member only.
 * <p>
 * No static cache, for the reason {@link GameDescriptorRegistry} gives (the overlay is a
 * user-writable directory).
 */
public final class C64GameDescriptors {

	/** {@code Program Info} key: path of the descriptor file that resolved (as NES's). */
	static final String DESCRIPTOR_PROPERTY = "Retro Machines.C64 Game Descriptor";
	/** {@code Program Info} key: the resolved {@code game.id}. */
	static final String GAME_ID_PROPERTY = "Retro Machines.C64 Game";
	/** {@code Program Info} key: the resolved member's {@code name}. */
	static final String MEMBER_NAME_PROPERTY = "Retro Machines.C64 Game Member";
	/** {@code Program Info} key: the program's content sha256 (the member key). */
	static final String MEMBER_SHA_PROPERTY = "Retro Machines.C64 Member SHA256";

	private C64GameDescriptors() {
	}

	/** One compiled C64 descriptor document and where it came from. */
	record Descriptor(String path, boolean overlay, JsonObject doc) {
		String gameId() {
			return doc.getAsJsonObject("game").get("id").getAsString();
		}
	}

	/**
	 * The effective descriptor for one program: the matched game document and the matched member.
	 * Consumers (e.g. the Forth work, grm-arbi.3) merge {@link #gameForth()} and
	 * {@link #memberForth()} themselves; {@link #entries()} is already merged here.
	 */
	public record Resolution(String path, boolean overlay, String gameId, String gameTitle,
			String memberName, String sha256, JsonObject game, JsonObject member) {

		/** Game-level {@code forth:} mapping verbatim, or {@code null} when the game has none. */
		public JsonObject gameForth() {
			return optObject(game, "forth");
		}

		/** Member-level {@code forth:} mapping verbatim (expected: {@code names}), or null. */
		public JsonObject memberForth() {
			return optObject(member, "forth");
		}

		/**
		 * The effective {@code entries:}: the game-level list, then the member's; a member entry
		 * at an address replaces the game-level entry at that address. Each element is the
		 * compiled {@code {addr, name, kind, [comment]}} object.
		 */
		public List<JsonObject> entries() {
			Map<Integer, JsonObject> byAddr = new LinkedHashMap<>();
			for (JsonObject source : new JsonObject[] { game, member }) {
				if (source.has("entries")) {
					for (JsonElement e : source.getAsJsonArray("entries")) {
						JsonObject entry = e.getAsJsonObject();
						byAddr.put(entry.get("addr").getAsInt(), entry);
					}
				}
			}
			return new ArrayList<>(byAddr.values());
		}

		private static JsonObject optObject(JsonObject o, String key) {
			return o.has(key) && o.get(key).isJsonObject() ? o.getAsJsonObject(key) : null;
		}
	}

	/** Lower-case hex SHA-256 of {@code bytes}. */
	static String sha256(byte[] bytes) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	/** Resolves a provider's whole content (see class comment); never throws, null = no match. */
	public static Resolution resolve(ByteProvider provider, MessageLog log) {
		try {
			return resolve(sha256(provider.readBytes(0, provider.length())), log);
		}
		catch (IOException | RuntimeException e) {
			log.appendMsg("C64 game descriptor lookup skipped: " + e);
			return null;
		}
	}

	/** Scans (fresh, overlay first) and resolves the member with content sha256 {@code sha}. */
	public static Resolution resolve(String sha, MessageLog log) {
		return resolve(scan(log), sha, log);
	}

	/**
	 * Re-resolves the descriptor recorded in an imported program's Program Info (for analyzers,
	 * which have no provider), or {@code null} when none was recorded or it no longer resolves.
	 */
	public static Resolution forProgram(Program program, MessageLog log) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		String sha = info.getString(MEMBER_SHA_PROPERTY, null);
		if (sha == null || info.getString(DESCRIPTOR_PROPERTY, null) == null) {
			return null;
		}
		return resolve(sha, log);
	}

	/** Records a resolution in Program Info (the keys above). */
	static void record(Program program, Resolution r) {
		Options info = program.getOptions(Program.PROGRAM_INFO);
		info.setString(DESCRIPTOR_PROPERTY, r.path());
		info.setString(GAME_ID_PROPERTY, r.gameId());
		info.setString(MEMBER_NAME_PROPERTY, r.memberName());
		info.setString(MEMBER_SHA_PROPERTY, r.sha256());
	}

	/**
	 * Pure resolution over already-scanned candidates. The overlay tier decides when it has any
	 * claim on {@code sha} (shadowed curated claims are logged); two claims in the deciding tier
	 * (two members, in one file or two) refuse BOTH, as {@link GameDescriptorRegistry} does.
	 */
	static Resolution resolve(List<Descriptor> candidates, String sha, MessageLog log) {
		String key = sha.toLowerCase(Locale.ROOT);
		List<Resolution> overlay = new ArrayList<>();
		List<Resolution> curated = new ArrayList<>();
		for (Descriptor d : candidates) {
			for (JsonElement me : d.doc().getAsJsonArray("members")) {
				JsonObject m = me.getAsJsonObject();
				if (m.get("sha256").getAsString().equals(key)) {
					Resolution r = new Resolution(d.path(), d.overlay(), d.gameId(),
						d.doc().getAsJsonObject("game").get("title").getAsString(),
						m.get("name").getAsString(), key, d.doc(), m);
					(d.overlay() ? overlay : curated).add(r);
				}
			}
		}
		List<Resolution> deciding = overlay.isEmpty() ? curated : overlay;
		if (deciding.isEmpty()) {
			return null;
		}
		if (deciding.size() > 1) {
			List<String> paths = new ArrayList<>();
			for (Resolution r : deciding) {
				paths.add(r.path() + " ('" + r.gameId() + "' member '" + r.memberName() + "')");
			}
			log.appendMsg("multiple C64 game descriptors claim sha256 " + key + ": " + paths +
				"; ignoring all of them (ambiguous match)");
			return null;
		}
		Resolution winner = deciding.get(0);
		if (!overlay.isEmpty()) {
			for (Resolution shadowed : curated) {
				log.appendMsg("overlay C64 game descriptor " + winner.path() + " ('" +
					winner.gameId() + "') shadows curated " + shadowed.path() + " ('" +
					shadowed.gameId() + "') for sha256 " + key + "; the overlay wins");
			}
		}
		return winner;
	}

	/** Every available C64 descriptor (overlay then curated); fresh on every call. */
	static List<Descriptor> scan(MessageLog log) {
		List<Descriptor> found = new ArrayList<>(scanOverlay(
			GameDescriptorRegistry.overlayFiles(), log));
		found.addAll(scanCurated(log));
		return found;
	}

	/** As {@link GameDescriptorRegistry#scanOverlay}: a bad file costs only itself. */
	static List<Descriptor> scanOverlay(List<File> files, MessageLog log) {
		List<Descriptor> found = new ArrayList<>();
		List<File> sorted = new ArrayList<>(files);
		sorted.sort(Comparator.comparing(File::getPath));
		for (File file : sorted) {
			GameCompiler.CompileResult result = GameCompiler.compileOverlay(file);
			if (!result.ok()) {
				for (String error : result.errors()) {
					log.appendMsg("Skipping overlay game descriptor: " + error);
				}
				continue;
			}
			JsonObject doc = new Gson().toJsonTree(result.gameDoc()).getAsJsonObject();
			Descriptor d = parse(doc, file.getPath(), true);
			if (d != null) {
				found.add(d);
			}
		}
		return found;
	}

	static List<Descriptor> scanCurated(MessageLog log) {
		List<Descriptor> found = new ArrayList<>();
		for (ResourceFile gmapFile : Application.findFilesByExtensionInMyModule(".gmap")) {
			ResourceFile parent = gmapFile.getParentFile();
			if (parent == null || !"games".equals(parent.getName())) {
				continue;
			}
			String path = "games/" + gmapFile.getName();
			try (InputStreamReader reader =
				new InputStreamReader(gmapFile.getInputStream(), StandardCharsets.UTF_8)) {
				Descriptor d = parse(JsonParser.parseReader(reader).getAsJsonObject(), path, false);
				if (d != null) {
					found.add(d);
				}
			}
			catch (Exception e) {
				log.appendMsg("Skipping unparseable game descriptor " + path + ": " +
					e.getMessage());
			}
		}
		return found;
	}

	/** The C64 descriptor in {@code doc}, or {@code null} when it is not one (silently). */
	static Descriptor parse(JsonObject doc, String path, boolean overlay) {
		if (!doc.has("game") || !doc.get("game").isJsonObject()) {
			return null;
		}
		JsonObject game = doc.getAsJsonObject("game");
		if (!game.has("platform") ||
			!GameCompiler.PLATFORM_C64.equals(game.get("platform").getAsString()) ||
			!doc.has("members") || !doc.get("members").isJsonArray()) {
			return null;
		}
		JsonArray members = doc.getAsJsonArray("members");
		return members.isEmpty() ? null : new Descriptor(path, overlay, doc);
	}
}
