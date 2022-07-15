import logging

import binsync.data
from binsync.common.ui.force_push.panels.functions_table import QFunctionTable
from binsync.common.ui.force_push.panels.global_panel import QGlobalsTable
from binsync.common.ui.qt_objects import (
    QLabel,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    Signal
)

l = logging.getLogger(__name__)

class ForcePushUI(QWidget):
    update_ready = Signal()
    def __init__(self, controller, parent=None):
        super(ForcePushUI, self).__init__(parent)
        self.controller = controller

        self.tables = {}
        self._init_widgets()

        # register controller callback
        self.update_ready.connect(self.reload)
        self.controller.ui_callback = self.update_callback

    def update_callback(self):
        """
        This function will be called in another thread, so the work
        done here is guaranteed to be thread safe.
        @return:
        """
        self._update_table_data()
        self.update_ready.emit()

    def reload(self):
        # check if connected
        if self.controller and self.controller.check_client():
            self._reload_tables()

        # update status
        status = self.controller.status_string() if self.controller else "Disconnected"
        self._status_label.setText(status)

    def closeEvent(self, event):
        if self.controller is not None:
            self.controller.client_init_callback = None

    def _init_widgets(self):
        # status bar
        self._status_label = QLabel(self)
        self._status_label.setText(self.controller.status_string())
        self._status_bar = QStatusBar(self)
        self._status_bar.addPermanentWidget(self._status_label)

        # control box
        control_layout = QVBoxLayout()

        # tabs for panel_tabs
        self.tabView = QTabWidget()
        self.tabView.setContentsMargins(0, 0, 0, 0)

        # add panel_tabs to tabs
        self._func_table = QFunctionTable(self.controller, load_from = "decompiler")
        self._global_table = QGlobalsTable(self.controller, load_from = "decompiler")

        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._global_table, "Globals")

        self.tables.update({
            "functions": self._func_table,
            "globals": self._global_table
        })

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabView)
        main_layout.addWidget(self._status_bar)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _reload_tables(self):
        for _, table in self.tables.items():
            table.reload()

    def _update_table_data(self):
        for _, table in self.tables.items():
            table.update_table()
