import logging

from .. import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QWidget, QCheckBox, QVBoxLayout, QLabel, QComboBox, QHBoxLayout, QGroupBox, QPushButton
    from PySide2.QtCore import Qt
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QWidget, QCheckBox, QVBoxLayout, QLabel, QComboBox, QHBoxLayout, QGroupBox, QPushButton
    from PySide6.QtCore import Qt
else:
    from PyQt5.QtWidgets import QWidget, QCheckBox, QVBoxLayout, QLabel, QComboBox, QHBoxLayout, QGroupBox, QPushButton
    from PyQt5.QtCore import Qt

from ..utils import QNumericItem, friendly_datetime
from ...controller import BinSyncController

l = logging.getLogger(__name__)

class QSettingsPanel(QWidget):
    def __init__(self, controller: BinSyncController, parent=None):
        super(QWidget, self).__init__(parent)
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

    def _handle_sync_level_change(self):
        print("aaa")

    def _handle_hide_press(self):
        import idaapi
        idaapi.close_widget(self.controller.plugin.wrapper.twidget, 0)


    def _init_widgets(self):
        self._debug_log_toggle = QCheckBox("Toggle Debug Logging")
        self._debug_log_toggle.setToolTip("Toggles the logging of events BinSync developers care about.")
        self._debug_log_toggle.stateChanged.connect(self._handle_debug_toggle)

        self._sync_level_label = QLabel("Sync Level")
        self._sync_level_label.setToolTip(
            """<html>
            <p>
            <b>WARNING: UNSUPPORTED CURRENTLY</b>
            Defines which method is used to sync artifacts from another user.<br>
            <b>Non-Conflicting</b>: Only syncs artifacts that are not currently defined by you, so nothing is ever overwritten.<br>
            <b>Overwrite</b>: Syncs all artifacts regardless of your defined ones, overwriting everything.<br>
            <b>Manual</b>: You pick which artifacts are synced via the UI.
            </p>
            </html>
            """)
        self._sync_level_label.setTextFormat(Qt.RichText)
        self._sync_level_combobox = QComboBox()
        self._sync_level_combobox.addItems(["Non-Conflicting", "Overwrite", "Manual"])
        self._sync_level_combobox.currentIndexChanged.connect(self._handle_sync_level_change)
        sync_level_group = QGroupBox()
        sync_level_group.setLayout(QHBoxLayout())
        sync_level_group.layout().setContentsMargins(0, 0, 0, 0)
        sync_level_group.layout().addWidget(self._sync_level_label)
        sync_level_group.layout().addWidget(self._sync_level_combobox)


        self._btn_hide_binsync = QPushButton("Hide BinSync")
        self._btn_hide_binsync.setToolTip("Unloads BinSync. For when you're unhappy with it.")
        self._btn_hide_binsync.pressed.connect(self._handle_hide_press)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(1, 1, 1, 1)
        main_layout.setSpacing(20)
        main_layout.setAlignment(Qt.AlignTop)
        main_layout.addWidget(sync_level_group)
        main_layout.addWidget(self._debug_log_toggle)
        main_layout.addWidget(self._btn_hide_binsync)

        self.setLayout(main_layout)

