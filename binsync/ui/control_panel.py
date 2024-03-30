import logging

import libbs.artifacts
from binsync.ui.panel_tabs.activity_table import QActivityTable
from binsync.ui.panel_tabs.ctx_table import QCTXTable
from binsync.ui.panel_tabs.functions_table import QFunctionTable
from binsync.ui.panel_tabs.globals_table import QGlobalsTable
from binsync.ui.panel_tabs.util_panel import QUtilPanel
from libbs.ui.qt_objects import (
    QLabel,
    QMenu,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    Signal,
    Slot
)

l = logging.getLogger(__name__)

class QContextStatusBar(QStatusBar):
    def __init__(self, controller, parent = None):
        super(QContextStatusBar, self).__init__(parent)
        self.controller = controller

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_context_context_menu")
        if self.controller.last_ctx:
            ctx_name = self.controller.last_ctx.name
            ctx_addr = self.controller.last_ctx.addr
            menu.addAction(f"Force Push {ctx_name}@{hex(ctx_addr)}", lambda : self.controller.force_push_functions([ctx_addr]))
            menu.popup(self.mapToGlobal(event.pos()))

class ControlPanel(QWidget):
    update_ready = Signal(str)
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

    def update_callback(self, states):
        """
        This function will be called in another thread, so the work
        done here is guaranteed to be thread safe.

        @return:
        """
        self._update_table_data(states)
        status = self.controller.status_string() if self.controller else "Disconnected"
        self.update_ready.emit(status)

    def ctx_callback(self, states):
        if isinstance(self.controller.last_ctx, libbs.artifacts.Function):
            self._ctx_table.update_table(states, new_ctx=self.controller.last_ctx.addr)

        self.ctx_change.emit()

    @Slot(str)
    def reload(self, status):
        # update status
        self._status_label.setText(status)

    def closeEvent(self, event):
        if self.controller is not None:
            self.controller.client_init_callback = None

    def _init_widgets(self):
        # status bar
        self._status_label = QLabel(self)
        self._status_label.setText(self.controller.status_string())
        self._status_bar = QContextStatusBar(self.controller, self)
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
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0,0,0,0)


        self.setLayout(main_layout)

    def _reload_ctx(self):
        ctx_name = self.controller.last_ctx.name or ""
        ctx_name = ctx_name[:12] + "..." if len(ctx_name) > 12 else ctx_name
        self._status_bar.showMessage(f"{ctx_name}@{hex(self.controller.last_ctx.addr)}")
        self._ctx_table.reload()

    def _update_table_data(self, states):

        for _, table in self.tables.items():
            table.update_table(states)

        self._ctx_table.update_table(states)
