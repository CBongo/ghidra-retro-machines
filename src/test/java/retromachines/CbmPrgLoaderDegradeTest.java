package retromachines;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.function.Consumer;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;

/**
 * Drives {@link C64PrgLoader#load} against crafted/malformed maps (bead grm-abg), covering the
 * grm-z15 #4 degrade paths end to end. The crafted maps are the compiled
 * {@code data/machines/c64.map} with one edit each, handed in through the package-private
 * {@code loadMap()} seam of a TEST-ONLY subclass (a main-side loader would be discovered by
 * ClassSearcher; Application.findDataFileInAnyModule cannot see test resources).
 */
public class CbmPrgLoaderDegradeTest extends AbstractBundledLanguageTest {

	private static final class CraftedMapLoader extends C64PrgLoader {
		private final JsonObject map;

		CraftedMapLoader(JsonObject map) {
			this.map = map;
		}

		@Override
		JsonObject loadMap() {
			return map;
		}
	}

	private static JsonObject craftedMap(Consumer<JsonObject> edit) throws IOException {
		File f = new File(System.getProperty(MODULE_DIR_PROPERTY), "data/machines/c64.map");
		JsonObject map = JsonParser.parseString(
			Files.readString(f.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();
		edit.accept(map);
		return map;
	}

	/** Runs load() on a PRG of {@code payload} bytes at {@code loadAddr}; returns the log. */
	private static MessageLog runLoad(JsonObject map, int loadAddr, int payload)
			throws Exception {
		byte[] prg = new byte[2 + payload];
		prg[0] = (byte) (loadAddr & 0xFF);
		prg[1] = (byte) (loadAddr >> 8);
		for (int i = 0; i < payload; i++) {
			prg[2 + i] = (byte) 0xEA;
		}
		ProgramBuilder builder = new ProgramBuilder("Test", "6510:LE:16:default");
		ProgramDB program = builder.getProgram();
		MessageLog log = new MessageLog();
		ImporterSettings settings = new ImporterSettings(
			new ByteArrayProvider("t.prg", prg), "t.prg", null, null, false, null,
			List.<Option>of(), new Object(), log, TaskMonitor.DUMMY);
		int tx = program.startTransaction("load");
		boolean commit = false;
		try {
			new CraftedMapLoader(map).load(program, settings);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		return log;
	}

	private static void breakBanking(JsonObject map) {
		map.getAsJsonObject("banking").remove("states");
	}

	@Test
	public void incompleteBankingWithPrgInWindowOccupantFailsCleanly() throws Exception {
		JsonObject map = craftedMap(CbmPrgLoaderDegradeTest::breakBanking);
		try {
			runLoad(map, 0xA000, 4); // RAM_A000, a banked-window occupant
			fail("expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("banking section is incomplete"));
			assertTrue(e.getMessage(), e.getMessage().contains("RAM_A000"));
		}
	}

	@Test
	public void incompleteBankingWithPrgInPlainRamStillImports() throws Exception {
		JsonObject map = craftedMap(CbmPrgLoaderDegradeTest::breakBanking);
		MessageLog log = runLoad(map, 0x0801, 4);
		assertTrue(log.toString(), log.toString().contains("banking section incomplete"));
	}

	@Test
	public void windowsLessMapDoesNotNpe() throws Exception {
		JsonObject map = craftedMap(m -> {
			m.remove("windows");
			m.remove("banking");
		});
		MessageLog log = runLoad(map, 0x0801, 4);
		assertNotNull(log);
		assertEquals(false, log.toString().contains("banking section incomplete"));
	}
}
