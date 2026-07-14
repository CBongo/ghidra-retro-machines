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
import java.awt.Component;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.util.Option;

/**
 * A loader {@link Option} for a path to an on-disk file (used by {@link C64PrgLoader} for
 * optional user-supplied ROM dumps). Its value is the path as a {@code String}.
 *
 * <p>The custom editor is an <b>editable</b> text field the user can type or paste a path
 * into directly, plus a <b>Browse</b> button that opens a local-filesystem
 * {@link GhidraFileChooser}. This differs deliberately from Ghidra's shipped
 * {@code DomainFileOption}, which uses a read-only field and a {@code DataTreeDialog} that
 * browses files <em>inside a Ghidra project</em> — here we need a real file on disk.
 *
 * <p>The option also carries a command-line argument, so a headless import can set the
 * path without the GUI editor.
 */
public class RomFileOption extends Option {

	/**
	 * @param name  the option name shown in the import dialog
	 * @param value the initial path (empty string = not supplied)
	 * @param arg   the command-line argument for headless imports
	 */
	public RomFileOption(String name, String value, String arg) {
		super(name, value, String.class, arg);
	}

	@Override
	public Component getCustomEditorComponent() {
		String initial = getValue() == null ? "" : getValue().toString();
		JTextField textField = new JTextField(initial);
		textField.setColumns(24);
		// Editable: the path can be typed/pasted directly; every edit updates the value.
		textField.getDocument().addDocumentListener(new DocumentListener() {
			private void sync() {
				setValue(textField.getText());
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				sync();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				sync();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				sync();
			}
		});

		JButton browse = new BrowseButton();
		browse.addActionListener(e -> {
			GhidraFileChooser chooser = new GhidraFileChooser(textField);
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setTitle("Choose file: " + getName());
			String current = textField.getText();
			if (current != null && !current.isBlank()) {
				chooser.setSelectedFile(new File(current.trim()));
			}
			File chosen = chooser.getSelectedFile(); // shows the modal chooser
			chooser.dispose();
			if (chosen != null) {
				textField.setText(chosen.getAbsolutePath()); // document listener updates the value
			}
		});

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(textField, BorderLayout.CENTER);
		panel.add(browse, BorderLayout.EAST);
		return panel;
	}

	@Override
	public Class<?> getValueClass() {
		return String.class;
	}

	@Override
	public Option copy() {
		String value = getValue() == null ? "" : getValue().toString();
		return new RomFileOption(getName(), value, getArg());
	}
}
