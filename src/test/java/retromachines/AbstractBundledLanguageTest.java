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
import java.util.HashMap;
import java.util.Map;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.GModule;
import ghidra.util.exception.AssertException;
import utility.application.ApplicationLayout;

/**
 * Base class for JUnit tests that need THIS module's bundled sleigh languages
 * (bead grm-2pi) -- {@code 6510:LE:16:default} and its variants.
 * <p>
 * Ghidra locates languages by scanning <em>module data directories</em>, not the java
 * classpath, so no amount of {@code testImplementation} wiring makes {@code data/languages}
 * visible. The stock {@link GhidraTestApplicationLayout} discovers modules only under the
 * Ghidra install's application roots ({@code findGhidraModules()}), which is why
 * {@code 6502:LE:16:default} resolves from a plain {@link AbstractGenericTest} and
 * {@code 6510:LE:16:default} does not. Its {@code findExtensionInstallationDirectories()}
 * points at {@code <userTempDir>/ExtensionInstallDir}, so the
 * {@code -Dapplication.settingsdir} redirection that {@code tools/banktest/run-banktest.sh}
 * uses for the headless tier does not carry over here either.
 * <p>
 * The supported seam is {@link AbstractGenericTest#createApplicationLayout()}, which Ghidra's
 * own tests already override this way (see {@code DWARFRegisterMappingsTest} and
 * {@code TutorialDebuggerScreenShots} in the Ghidra source tree). We return a layout that
 * merges this repo in as an extra module. The repo root carries {@code Module.manifest}, so
 * {@link GModule} treats it exactly like a stock processor module and finds
 * {@code data/languages/*.ldefs} beneath it.
 * <p>
 * This reads the working tree directly -- no extension install, no {@code %APPDATA%}, no
 * shared settings dir -- so it stays hermetic and safe under parallel git worktrees. The
 * module directory arrives as the {@code grm.moduleDir} system property, set by the
 * {@code test} task in build.gradle, which also {@code dependsOn sleighCompile} so the
 * (gitignored) {@code .sla} files exist by the time tests run.
 */
public abstract class AbstractBundledLanguageTest extends AbstractGenericTest {

	/** Set by build.gradle's {@code test} task; the root of this Ghidra module. */
	public static final String MODULE_DIR_PROPERTY = "grm.moduleDir";

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		ResourceFile moduleRoot = resolveModuleRoot();
		return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
			@Override
			protected Map<String, GModule> findGhidraModules() throws IOException {
				Map<String, GModule> modules = new HashMap<>(super.findGhidraModules());
				modules.put(moduleRoot.getName(),
					new GModule(applicationRootDirs, moduleRoot));
				return modules;
			}
		};
	}

	/**
	 * The module root to graft into the test layout. Fails loudly rather than silently
	 * falling back: a missing property here would surface as a confusing
	 * {@code LanguageNotFoundException} in every subclass instead of a plain "you ran this
	 * outside Gradle" message.
	 */
	private static ResourceFile resolveModuleRoot() {
		String configured = System.getProperty(MODULE_DIR_PROPERTY);
		if (configured == null || configured.isBlank()) {
			throw new AssertException("System property " + MODULE_DIR_PROPERTY +
				" is not set -- bundled languages cannot be located. It is set by the " +
				"`test` task in build.gradle; run these tests through Gradle (or set it " +
				"manually in an IDE run configuration).");
		}
		File dir = new File(configured);
		if (!new File(dir, "Module.manifest").isFile()) {
			throw new AssertException(MODULE_DIR_PROPERTY + "=" + configured +
				" does not look like a Ghidra module (no Module.manifest).");
		}
		return new ResourceFile(dir);
	}
}
