import logging
import time

import binsync.data
from binsync.common.ui.panel_tabs.activity_table import QActivityTable
from binsync.common.ui.panel_tabs.ctx_table import QCTXTable
from binsync.common.ui.panel_tabs.functions_table import QFunctionTable
from binsync.common.ui.panel_tabs.globals_table import QGlobalsTable
from binsync.common.ui.panel_tabs.util_panel import QUtilPanel
from binsync.common.ui.qt_objects import (
    QLabel,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    Signal
)

l = logging.getLogger(__name__)

class ControlPanel(QWidget):
    update_ready = Signal()
    ctx_change = Signal()

    def __init__(self, controller, parent=None):
        super(ControlPanel, self).__init__(parent)
        self.controller = controller

        self.tables = {}
        self._init_widgets()

        # register controller callback
        self.update_ready.connect(self.reload)
        self.controller.ui_callback = self.update_callback

        self.ctx_change.connect(self._reload_ctx)
        self.controller.ctx_change_callback = self.ctx_callback

    def update_callback(self):
        """
        This function will be called in another thread, so the work
        done here is guaranteed to be thread safe.

        @return:
        """
        self._update_table_data()
        self.update_ready.emit()

    def ctx_callback(self):
        if isinstance(self.controller.last_ctx, binsync.data.Function):
            self._ctx_table.model.update_table(new_ctx=self.controller.last_ctx.addr)

        self.ctx_change.emit()

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

        # add panel_tabs to tabs
        self._ctx_table = QCTXTable(self.controller)
        self._func_table = QFunctionTable(self.controller)
        self._global_table = QGlobalsTable(self.controller)
        self._activity_table = QActivityTable(self.controller)
        self._utilities_panel = QUtilPanel(self.controller)

        self.tabView.addTab(self._ctx_table, "Context")
        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._global_table, "Globals")
        self.tabView.addTab(self._activity_table, "Activity")
        self.tabView.addTab(self._utilities_panel, "Utilities")

        self.tables.update({
            "functions": self._func_table,
            "globals": self._global_table,
            "activity": self._activity_table
        })

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabView)
        main_layout.addWidget(self._status_bar)

        self.setLayout(main_layout)

    def _reload_ctx(self):
        ctx_name = self.controller.last_ctx.name or ""
        ctx_name = ctx_name[:12] + "..." if len(ctx_name) > 12 else ctx_name
        self._status_bar.showMessage(f"{ctx_name}@{hex(self.controller.last_ctx.addr)}")

    def _reload_tables(self):
        for _, table in self.tables.items():
            table.reload()

    def _update_table_data(self):
        for _, table in self.tables.items():
            table.update_table()

        self._ctx_table.update_table()
        self._func_table.update_table()