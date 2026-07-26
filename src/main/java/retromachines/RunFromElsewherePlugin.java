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

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JComboBox;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.AddressInput;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitor;

/**
 * The GUI front-end for run-from-elsewhere transfers (grm-1.7.1.1): the same manual transfer
 * {@code ghidra_scripts/RunFromElsewhereTransfer.java} performs headless, driven from a dialog and
 * seeded from wherever the cursor is.
 *
 * <p><b>This class is a pure adapter and must stay one.</b> It reads dialog fields, builds one
 * {@link RunFromElsewhere.Request}, and calls {@link RunFromElsewhere#apply}; it contains no
 * transfer logic, no placement decision, and no validation beyond "the field is filled in". That
 * is a hard rule rather than a style preference, because this class has <em>no automated
 * regression path at all</em>: docs/testing.md rules out {@code AbstractGuiTest}/{@code TestEnv}
 * (the headed test module is absent from the binary install) and the Tier-3 golden harness is
 * headless-only, so nothing here is covered by the acceptance gate. Every behavior worth testing
 * therefore lives behind the facade, where {@code RunFromElsewhereTest} and the {@code rfemanual}
 * headless fixture reach it. Anything added here that a test could not see is untested by
 * construction -- put it in {@link RunFromElsewhere} instead.
 *
 * <p><b>Why the work runs as a command, not in the action.</b> A Swing action holds no
 * transaction, and {@link RunFromElsewhere#apply} refuses to run without one. Submitting a
 * {@link BackgroundCommand} through {@link PluginTool#executeBackgroundCommand} hands the work to
 * {@code BackgroundCommandTask.run} (BackgroundCommandTask.java:80), which opens the transaction
 * around {@code applyTo} and names the undo entry after the command -- so the user gets one
 * cancellable, correctly labeled "Run From Elsewhere Transfer" undo step off the event thread.
 *
 * <p>No {@code data/ExtensionPoint.manifest} entry is needed: {@code Plugin} is a global extension
 * point suffix (Ghidra/Framework/Project/data/ExtensionPoint.manifest:2) and
 * {@code ClassSearcher.loadExtensionPointSuffixes} unions the suffixes declared by every module,
 * so this repo's manifest (which names only {@code BankSwitchStrategy}) adds to that set rather
 * than narrowing it. The class-name suffix is the whole registration.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Run From Elsewhere Transfer",
	description = RunFromElsewherePlugin.DESCRIPTION
)
//@formatter:on
public class RunFromElsewherePlugin extends ProgramPlugin {

	static final String DESCRIPTION =
		"Materializes a run-from-elsewhere transfer by hand: copies a range of bytes to the " +
			"address the program copies them to at run time, so self-modifying/relocating code " +
			"is visible where the CPU executes it. The manual counterpart to the Retro Copy " +
			"Loop analyzer, for copies no recognizer can see.";

	/** Bookmark category for provenance: the front-end's own name, per apply()'s contract. */
	private static final String CATEGORY = "RunFromElsewhere";
	private static final String ACTION_NAME = "Run From Elsewhere Transfer";
	private static final String MENU_ITEM = ACTION_NAME + "...";

	public RunFromElsewherePlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		ListingContextAction action = new ListingContextAction(ACTION_NAME, getName()) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				Program program = context.getProgram();
				if (program == null) {
					return;
				}
				tool.showDialog(new TransferDialog(program, context.getAddress()));
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return context.getProgram() != null;
			}
		};
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_TOOLS, "Retro Machines", MENU_ITEM }));
		action.setPopupMenuData(new MenuData(new String[] { "Retro Machines", MENU_ITEM }));
		action.setDescription(DESCRIPTION);
		tool.addAction(action);
	}

	/**
	 * Collects the same fields the script's arguments carry. {@link AddressInput} rather than a
	 * plain text field for the three addresses, because it offers the program's address spaces in
	 * a combo -- the NES bank-overlay case needs a source that lives in an overlay space, which a
	 * bare hex field cannot express.
	 */
	private class TransferDialog extends DialogComponentProvider {

		private final Program program;

		private final AddressInput srcField = new AddressInput();
		private final AddressInput dstField = new AddressInput();
		private final AddressInput entryField = new AddressInput();
		private final IntegerTextField lenField = new IntegerTextField(10);
		private final JComboBox<TransferTransform> transformBox =
			new GComboBox<>(TransferTransform.values());
		private final JComboBox<TransferTarget> targetBox = new GComboBox<>(TransferTarget.values());
		private final GCheckBox disassembleBox = new GCheckBox("Disassemble the copy");
		private final GCheckBox functionBox = new GCheckBox("Create a function at the entry point");

		TransferDialog(Program program, Address contextAddress) {
			super(ACTION_NAME, true);
			this.program = program;

			srcField.setProgram(program);
			dstField.setProgram(program);
			entryField.setProgram(program);
			if (contextAddress != null) {
				// Seed the source from the cursor: the user is normally sitting on the copy
				// routine's operand when they reach for this.
				srcField.setAddress(contextAddress);
			}
			lenField.setDecimalMode();

			addWorkPanel(buildPanel());
			addOKButton();
			addCancelButton();
			setRememberSize(false);
		}

		private JComponent buildPanel() {
			JPanel fields = new JPanel(new PairLayout(6, 8));
			fields.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			fields.add(new GLabel("Source:"));
			fields.add(srcField);
			fields.add(new GLabel("Destination:"));
			fields.add(dstField);
			fields.add(new GLabel("Length (bytes):"));
			fields.add(lenField.getComponent());
			fields.add(new GLabel("Entry point (optional):"));
			fields.add(entryField);
			fields.add(new GLabel("Transform:"));
			fields.add(transformBox);
			fields.add(new GLabel("Placement:"));
			fields.add(targetBox);

			JPanel toggles = new JPanel(new PairLayout(6, 8));
			toggles.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
			toggles.add(disassembleBox);
			toggles.add(functionBox);

			JPanel panel = new JPanel(new BorderLayout());
			panel.add(fields, BorderLayout.CENTER);
			panel.add(toggles, BorderLayout.SOUTH);
			return panel;
		}

		@Override
		protected void okCallback() {
			Address src = srcField.getAddress();
			Address dst = dstField.getAddress();
			// A blank entry field means "start at the destination", which is the Request default;
			// a filled-in but unparseable one is an error, not a silent default.
			Address entry = entryField.hasInput() ? entryField.getAddress() : null;
			int len = lenField.getIntValue();
			if (src == null || dst == null || len <= 0 ||
				(entryField.hasInput() && entry == null)) {
				setStatusText("Source, destination and a positive length are required, and any " +
					"entry point must be a valid address.");
				return;
			}

			RunFromElsewhere.Request request = RunFromElsewhere.request(src, dst, len)
					.transform((TransferTransform) transformBox.getSelectedItem())
					.target((TransferTarget) targetBox.getSelectedItem())
					.entryPoint(entry)
					.disassemble(disassembleBox.isSelected())
					.makeFunction(functionBox.isSelected())
					.originLabel("manual transfer");

			// Not applied here: this callback runs on the event thread with no transaction open.
			close();
			tool.executeBackgroundCommand(new TransferCommand(request), program);
		}
	}

	/** The transaction-owning wrapper around the one {@code apply} call. */
	private static class TransferCommand extends BackgroundCommand<Program> {

		private final RunFromElsewhere.Request request;

		TransferCommand(RunFromElsewhere.Request request) {
			super(ACTION_NAME, true, true, false);
			this.request = request;
		}

		@Override
		public boolean applyTo(Program program, TaskMonitor monitor) {
			MessageLog log = new MessageLog();
			RunFromElsewhere.Result result =
				RunFromElsewhere.apply(program, request, CATEGORY, monitor, log);
			if (!result.satisfied()) {
				// Surfaced by the tool as the command's failure status; apply() also logged it.
				setStatusMsg(result.detail());
				return false;
			}
			setStatusMsg("Materialized " + result.blockName() +
				(result.alreadyPresent() ? " (already present)" : "") + " [" + result.placement() +
				"]");
			return true;
		}
	}
}
