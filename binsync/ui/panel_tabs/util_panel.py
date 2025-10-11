import logging
import time
import requests
import urllib.parse

from binsync.controller import  MergeLevel
from libbs.ui.qt_objects import (
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
    QIntValidator,
    QThread,
    QObject,
    Signal
)
from binsync.ui.magic_sync_dialog import MagicSyncDialog
from binsync.ui.force_push import ForcePushUI
from binsync.ui.utils import no_concurrent_call
from binsync.controller import BSController
from binsync.extras import EXTRAS_AVAILABLE

l = logging.getLogger(__name__)


class QUtilPanel(QWidget):
    def __init__(self, controller: BSController, parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()

    def _init_widgets(self):

        #
        # Sync Options Group
        #

        sync_options_group = QGroupBox()
        sync_options_layout = QVBoxLayout()
        sync_options_group.setTitle("Sync Options")
        sync_options_group.setLayout(sync_options_layout)

        self._merge_level_label = QLabel("Sync Merge Level")
        self._merge_level_label.setToolTip(
            """<html>
            <p>
            Defines which method is used to sync artifacts from another user.<br>
            <b>Non-Conflicting</b>: Only syncs artifacts that are not currently defined by you, so nothing is ever overwritten.<br>
            <b>Overwrite</b>: Syncs all artifacts regardless of your defined ones, overwriting everything.<br>
            <b>Merge</b>: You pick which artifacts are synced via the UI. <b>Unimplemented.</b>
            </p>
            </html>
            """)
        self._merge_level_label.setTextFormat(Qt.RichText)
        self._merge_level_combobox = QComboBox()
        self._merge_level_combobox.addItems(["Non-Conflicting", "Overwrite", "Merge"])
        self._merge_level_combobox.currentIndexChanged.connect(self._handle_sync_level_change)

        sync_level_layout = QHBoxLayout()
        #sync_level_group.layout().setContentsMargins(0, 0, 0, 0)
        sync_level_layout.addWidget(self._merge_level_label)
        sync_level_layout.addWidget(self._merge_level_combobox)

        self._magic_sync_button = QPushButton("Magic Sync")
        self._magic_sync_button.clicked.connect(lambda: self._handle_magic_sync_button())
        self._magic_sync_button.setToolTip("Performs a best effort merge of all existing user data to your state, "
                                           "but won't affect your existing state (this uses a non-conflicting merge).")

        self._force_push_button = QPushButton("Force Push...")
        self._force_push_button.clicked.connect(self._handle_force_push_button)
        self._force_push_button.setToolTip("Manually select function and globals you would like to be force committed "
                                           "and pushed to your user branch on Git.")

        self._pull_segments_button = QPushButton("Pull Segments...")
        self._pull_segments_button.clicked.connect(self._handle_pull_segments_button)
        self._pull_segments_button.setToolTip("Manually select segments from other users to pull into your state.")

        self._auto_fast_sync = QCheckBox("Auto Fast Sync")
        self._auto_fast_sync.setToolTip("For any function you have not renamed, it auto grabs one from some user.")
        self._auto_fast_sync.setChecked(self.controller.do_safe_sync_all)
        self._auto_fast_sync.stateChanged.connect(self._handle_auto_fast_sync_toggle)

        self._enable_sync_preview = QCheckBox("Enable Precise Diff Preview")
        self._enable_sync_preview.setToolTip("When enabled, shows precise diff preview from your current decompiler state. When disabled, shows diff from master state.")
        self._enable_sync_preview.setChecked(self.controller.precise_diff_preview)
        self._enable_sync_preview.stateChanged.connect(self._handle_sync_preview_toggle)

        sync_options_layout.addLayout(sync_level_layout)
        #sync_options_group.layout().addWidget(self._magic_sync_button)
        sync_options_group.layout().addWidget(self._force_push_button)
        sync_options_group.layout().addWidget(self._pull_segments_button)
        sync_options_group.layout().addWidget(self._auto_fast_sync)
        sync_options_group.layout().addWidget(self._enable_sync_preview)

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

        self._auto_commit = QCheckBox("Disable Auto Committing")
        self._auto_commit.setToolTip("Disables the automatic committing of changes to your user branch. Any changes"
                                    "you make during this time will not be recorded by BinSync.")
        self._auto_commit.setChecked(not self.controller.auto_commit_enabled)
        self._auto_commit.stateChanged.connect(self._handle_auto_commit_toggle)

        self._auto_push = QCheckBox("Disable Auto Pushing")
        self._auto_push.setToolTip("Disables the automatic pushing of commits to your user branch.")
        self._auto_push.setChecked(not self.controller.auto_push_enabled)
        self._auto_push.stateChanged.connect(self._handle_auto_push_toggle)

        self._auto_pull = QCheckBox("Disable Auto Pulling")
        self._auto_pull.setToolTip("Disables the automatic pulling of commits from ALL branches.")
        self._auto_pull.setChecked(not self.controller.auto_pull_enabled)
        self._auto_pull.stateChanged.connect(self._handle_auto_pull_toggle)
        dev_options_layout.addWidget(self._auto_commit)
        dev_options_layout.addWidget(self._auto_push)
        dev_options_layout.addWidget(self._auto_pull)


        #
        # UI Options Group
        #

        ui_options_group = QGroupBox()
        ui_options_layout = QVBoxLayout()
        ui_options_group.setTitle("UI Options")
        ui_options_group.setLayout(ui_options_layout)

        _table_coloring_window_group = QHBoxLayout()
        _table_coloring_window_level_label = QLabel("Table Coloring Window (s)")
        _table_coloring_window_level_label.setToolTip("Window (in seconds) over which recently updated table entries are colored.")

        self._table_coloring_window_lineedit = QLineEdit()
        self._table_coloring_window_lineedit.setText(f"{self.controller.table_coloring_window}")
        intval = QIntValidator()
        intval.setRange(0, 60 * 60 * 24 * 7 * 52) #1 year in seconds
        self._table_coloring_window_lineedit.setValidator(intval)
        self._table_coloring_window_lineedit.setMaximumWidth(200)
        self._table_coloring_window_lineedit.textChanged.connect(self._handle_table_coloring_change)

        _table_coloring_window_group.addWidget(_table_coloring_window_level_label)
        _table_coloring_window_group.addWidget(self._table_coloring_window_lineedit)

        ui_options_layout.addLayout(_table_coloring_window_group)

        #
        # Save/Apply Options Group
        #

        self._save_apply_config_option = QPushButton("Save Config")
        self._save_apply_config_option.clicked.connect(self._handle_save_config_button)

        #
        # Final Layout
        #

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 20, 10, 20)
        main_layout.setSpacing(18)
        main_layout.setAlignment(Qt.AlignTop)
        main_layout.addWidget(sync_options_group)
        main_layout.addWidget(dev_options_group)
        main_layout.addWidget(ui_options_group)
        if EXTRAS_AVAILABLE:
            main_layout.addWidget(self._create_extras_group())
        main_layout.addWidget(self._save_apply_config_option)
        self.setLayout(main_layout)

    #
    # Extras GUI (only available if extras are installed)
    #

    def _create_extras_group(self):
        extras_group = QGroupBox()
        extras_layout = QVBoxLayout()
        extras_group.setTitle("BS Extras")

        #
        # AI Extras
        #

        progress_view_btn = QPushButton("Open Progress View...")
        progress_view_btn.clicked.connect(self._handle_progress_view)
        extras_layout.addWidget(progress_view_btn)

        # Binsync server
        self.client_thread = None
        connect_to_server_btn = QPushButton("Connect to Server...")
        connect_to_server_btn.clicked.connect(self._display_connect_to_server)
        extras_layout.addWidget(connect_to_server_btn)
        disconnect_from_server_btn = QPushButton("Disconnect from Server...")
        disconnect_from_server_btn.clicked.connect(self._disconnect_from_server)
        extras_layout.addWidget(disconnect_from_server_btn)
        
        extras_group.setLayout(extras_layout)
        
        return extras_group

    def _display_connect_to_server(self):
        # We are going to make it just connect to localhost for now without an actual display
        if not self.client_thread:
            self.client_thread = ClientThread()
            self.client_thread.start()
        else:
            l.info("You are already connected to a server!")
        
    def _disconnect_from_server(self):
        if self.client_thread:
            self.client_thread.stop()
            self.client_thread.quit()
            self.client_thread.wait() # Issue - will block on thread cleanup
            self.client_thread = None
        else:
            l.info("You are not currently connected to a server!")

    def _handle_progress_view(self):
        from ..progress_graph.progress_window import ProgressGraphWidget
        dialog = ProgressGraphWidget(graph=self.controller.deci.get_callgraph(), controller=self.controller, parent=self)
        dialog.show()
        dialog.exec_()

    #
    # Event Handlers
    #

    def _handle_auto_fast_sync_toggle(self, state):
        if state == Qt.Checked:
            l.info("Enabling auto fast sync!")
            self.controller.do_safe_sync_all = True
        else:
            l.info("Disabling auto fast sync!")
            self.controller.do_safe_sync_all = False

    def _handle_sync_preview_toggle(self, state):
        if state == Qt.Checked:
            l.info("Enabling precise diff preview!")
            self.controller.precise_diff_preview = True
        else:
            l.info("Disabling precise diff preview!")
            self.controller.precise_diff_preview = False

    def _handle_table_coloring_change(self):
        try:
            val = int(self._table_coloring_window_lineedit.text())
            self.controller.table_coloring_window = val
        except ValueError:
            pass

    def _handle_save_config_button(self):
        if not self.controller.config:
            return

        if self._debug_log_toggle.isChecked():
            self.controller.config.log_level = "debug"
        else:
            self.controller.config.log_level = "info"

        self.controller.config.merge_level = self.controller.merge_level

        self.controller.config.table_coloring_window = self.controller.table_coloring_window
        
        self.controller.config.precise_diff_preview = self.controller.precise_diff_preview

        if self.controller.config.save() is None:
            l.info("Error saving configuration file, check that the path '%s' is valid.", self.controller.config.save_location)
        else:
            l.info("Saved configuration file '%s'", self.controller.config.save_location)

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
        selected_opt = self._merge_level_combobox.itemText(index)
        if selected_opt == "Non-Conflicting":
            self.controller.merge_level = MergeLevel.NON_CONFLICTING
        elif selected_opt == "Overwrite":
            self.controller.merge_level = MergeLevel.OVERWRITE
        elif selected_opt == "Merge":
            self.controller.merge_level = MergeLevel.MERGE
        else:
            return
        l.debug("Sync level changed to: %s", selected_opt)

    @no_concurrent_call
    def _handle_magic_sync_button(self):
        dialog = MagicSyncDialog(self.controller)
        dialog.exec_()

        if not dialog.should_sync:
            return

        self.controller.magic_fill(preference_user=dialog.preferred_user)

    def _handle_force_push_button(self):
        self.popup = ForcePushUI(self.controller)
        self.popup.show()

    def _handle_pull_segments_button(self):
        from ..pull_segments_dialog import PullSegmentsDialog
        dialog = PullSegmentsDialog(self.controller)
        dialog.exec_()

    def _handle_auto_commit_toggle(self, state):
        if state == Qt.Checked:
            l.info("Disabling auto-commit!")
            self.controller.auto_commit_enabled = False
        else:
            self.controller.auto_commit_enabled = True

    def _handle_auto_push_toggle(self, state):
        if state == Qt.Checked:
            l.info("Disabling auto-push!")
            self.controller.auto_push_enabled = False
        else:
            self.controller.auto_push_enabled = True

    def _handle_auto_pull_toggle(self, state):
        if state == Qt.Checked:
            l.info("Disabling auto-pull!")
            self.controller.auto_pull_enabled = False
        else:
            self.controller.auto_pull_enabled = True

class ClientWorker(QObject):
    finished = Signal()
    def __init__(self):
        super().__init__()
        self.connected = False
        
    def run(self):
        host = "[::1]" # TODO: make host configurable
        port = 7962 # TODO: make port configurable
        self.server_url = f"http://{host}:{port}"
        parsed = urllib.parse.urlparse(self.server_url)
        if parsed.netloc != f"{host}:{port}":
            l.error("HOST AND PORT COMBINATION IS NOT VALID: NETLOC %s BUT HOST %s AND PORT %s",parsed.netloc,parsed.host,parsed.port)
        l.info(requests.get(self.server_url+"/connect").text)
        self.connected = True
        while self.connected:
            time.sleep(1)
        l.info(requests.get(self.server_url+"/disconnect").text)
        self.finished.emit()
        
        
    def stop(self):
        self.connected = False
        
        
class ClientThread(QThread):
    def __init__(self):
        super().__init__()
        self.worker = ClientWorker()

    def run(self):
        self.worker.run()
        
        
    def stop(self):
        self.worker.stop()
