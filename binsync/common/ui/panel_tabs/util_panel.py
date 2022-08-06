import logging

from binsync.common.controller import BinSyncController, SyncLevel
from binsync.common.ui.qt_objects import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    Qt,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QIntValidator
)
from binsync.common.ui.magic_sync_dialog import MagicSyncDialog
from binsync.common.controller import BinSyncController
from binsync.core.scheduler import SchedSpeed

l = logging.getLogger(__name__)


class QUtilPanel(QWidget):
    def __init__(self, controller: BinSyncController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _handle_debug_toggle(self):
        if self._debug_log_toggle.isChecked():
            logging.getLogger("binsync").setLevel("DEBUG")
            logging.getLogger("ida_binsync").setLevel("DEBUG")
            l.info("Logger has been set to level: DEBUG")
        else:
            logging.getLogger("binsync").setLevel("INFO")
            logging.getLogger("ida_binsync").setLevel("INFO")
            l.info("Logger has been set to level: INFO")

    def _handle_sync_level_change(self, index):
        selected_opt = self._sync_level_combobox.itemText(index)
        if selected_opt == "Non-Conflicting":
            self.controller.sync_level = SyncLevel.NON_CONFLICTING
        elif selected_opt == "Overwrite":
            self.controller.sync_level = SyncLevel.OVERWRITE
        elif selected_opt == "Merge":
            self.controller.sync_level = SyncLevel.MERGE
        else:
            return
        l.debug(f"Sync level changed to: {selected_opt}")

    def _handle_magic_sync_button(self):
        dialog = MagicSyncDialog(self.controller)
        dialog.exec_()

        if not dialog.should_sync:
            return

        self.controller.magic_fill(preference_user=dialog.preferred_user)

    def _handle_save_button(self):
        # handle table_coloring_window
        text = self._table_coloring_window_editor.text()
        if not text:
            return
        newval = int(text)
        self.controller.table_coloring_window = newval
        self.controller.config.table_coloring_window = newval

        # handle sync_level
        self.controller.config.sync_level = self.controller.sync_level

        # handle log_level
        if self._debug_log_toggle.isChecked():
            self.controller.config.log_level = "DEBUG"
        else:
            self.controller.config.log_level = "INFO"

        self.controller.config.save()

    def _init_widgets(self):

        #
        # Developer Options Group
        #

        dev_options_group = QGroupBox()
        dev_options_layout = QVBoxLayout()
        dev_options_group.setTitle("Developer Options")
        dev_options_group.setLayout(dev_options_layout)

        self._debug_log_toggle = QCheckBox("Toggle Debug Logging")
        self._debug_log_toggle.setToolTip("Toggles the logging of events BinSync developers care about.")
        self._debug_log_toggle.stateChanged.connect(self._handle_debug_toggle)
        dev_options_layout.addWidget(self._debug_log_toggle)

        #
        # Sync Options Group
        #

        sync_options_group = QGroupBox()
        sync_options_layout = QVBoxLayout()
        sync_options_group.setTitle("Sync Options")
        sync_options_group.setLayout(sync_options_layout)

        self._sync_level_label = QLabel("Sync Level")
        self._sync_level_label.setToolTip(
            """<html>
            <p>
            Defines which method is used to sync artifacts from another user.<br>
            <b>Non-Conflicting</b>: Only syncs artifacts that are not currently defined by you, so nothing is ever overwritten.<br>
            <b>Overwrite</b>: Syncs all artifacts regardless of your defined ones, overwriting everything.<br>
            <b>Merge</b>: You pick which artifacts are synced via the UI. <b>Unimplemented.</b>
            </p>
            </html>
            """)
        sync_level_opts = ["Non-Conflicting", "Overwrite", "Merge"]
        self._sync_level_label.setTextFormat(Qt.RichText)
        self._sync_level_combobox = QComboBox()
        self._sync_level_combobox.addItems(sync_level_opts)
        self._sync_level_combobox.currentIndexChanged.connect(self._handle_sync_level_change)
        if self.controller.sync_level == SyncLevel.NON_CONFLICTING:
            self._sync_level_combobox.setCurrentIndex(sync_level_opts.index("Non-Conflicting"))
        elif self.controller.sync_level == SyncLevel.OVERWRITE:
            self._sync_level_combobox.setCurrentIndex(sync_level_opts.index("Overwrite"))
        elif self.controller.sync_level == SyncLevel.MERGE:
            self._sync_level_combobox.setCurrentIndex(sync_level_opts.index("Merge"))

        sync_level_layout = QHBoxLayout()
        sync_level_layout.addWidget(self._sync_level_label)
        sync_level_layout.addWidget(self._sync_level_combobox)

        self._magic_sync_button = QPushButton("Initiate Magic Sync")
        self._magic_sync_button.pressed.connect(self._handle_magic_sync_button)
        self._magic_sync_button.setToolTip("Performs a best effort merge of all existing user data to your state, but won't affect your existing state (this uses a non-conflicting merge).")

        sync_options_layout.addLayout(sync_level_layout)
        sync_options_group.layout().addWidget(self._magic_sync_button)

        table_options_layout = QHBoxLayout()
        table_options_group = QGroupBox()
        table_options_group.setTitle("Table Options")
        table_options_group.setLayout(table_options_layout)

        self._table_coloring_window_label = QLabel("Table Coloring Window (seconds)")
        self._table_coloring_window_label.setToolTip("""<html>
            <p>
            The time period in which updates to the table are colored in seconds (default: 2 hours aka 7200s)
            </p>
            </html>
            """)

        validator = QIntValidator()
        validator.setBottom(0)
        validator.setTop(20*365*24*60*60)
        self._table_coloring_window_editor = QLineEdit()
        self._table_coloring_window_editor.setText(str(self.controller.table_coloring_window))
        self._table_coloring_window_editor.setValidator(validator)
        self._table_coloring_window_editor.setAlignment(Qt.AlignRight)
        self._table_coloring_window_editor.setMinimumWidth(50)

        table_options_layout.addWidget(self._table_coloring_window_label)
        table_options_layout.addStretch(100)
        table_options_layout.addWidget(self._table_coloring_window_editor)

        self._save_button = QPushButton("Save Configuration")
        self._save_button.pressed.connect(self._handle_save_button)


        #
        # Populate with settings from config if exists
        #
        if hasattr(self.controller.config, "log_level") and self.controller.config.log_level is not None:
            if self.controller.config.log_level == "DEBUG":
                self._debug_log_toggle.setChecked(True)
            elif self.controller.config.log_level == "INFO":
                self._debug_log_toggle.setChecked(False)


        #
        # Final Layout
        #

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 20, 10, 20)
        main_layout.setSpacing(18)
        main_layout.setAlignment(Qt.AlignTop)
        main_layout.addWidget(sync_options_group)
        main_layout.addWidget(dev_options_group)
        main_layout.addWidget(table_options_group)
        main_layout.addStretch()
        main_layout.addWidget(self._save_button)
        self.setLayout(main_layout)
