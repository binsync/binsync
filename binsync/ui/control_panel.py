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
    Slot,
    QToolTip,
    QRect,
    QCursor,
)

l = logging.getLogger(__name__)

class HoverLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tooltip = ""

    def enterEvent(self, event):
        QToolTip.showText(QCursor.pos(), self._tooltip, self, QRect(), 60000)
    
    def set_tooltip(self, tooltip:str):
        self._tooltip = tooltip

class QContextStatusBar(QStatusBar):
    def __init__(self, controller, parent = None):
        super(QContextStatusBar, self).__init__(parent)
        self.controller = controller

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setObjectName("binsync_context_context_menu")
        if self.controller.last_active_func:
            ctx_name = self.controller.last_active_func.name
            ctx_addr = self.controller.last_active_func.addr
            menu.addAction(f"Force Push {ctx_name}@{hex(ctx_addr)}", lambda : self.controller.force_push_functions([ctx_addr], use_decompilation=True))
            menu.popup(self.mapToGlobal(event.pos()))

class ControlPanel(QWidget):
    update_ready = Signal(str)
    ctx_change = Signal()

    def __init__(self, controller, parent=None):
        super(ControlPanel, self).__init__(parent)
        self.controller = controller

        self.tables = {}
        self._user_contexts = {}
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
        if isinstance(self.controller.last_active_func, libbs.artifacts.Function):
            self._ctx_table.update_table(states, new_ctx=self.controller.last_active_func.addr)

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
        self._context_info: HoverLabel|None = None # To be given a QLabel when needed

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

        # Connect signal from utility panel to function in activity table to facilitate displaying user locations for binsync Server extra
        self._utilities_panel.connected_to_server.connect(self._activity_table.add_live_addresses) 
        self._utilities_panel.server_context_change.connect(self._activity_table.update_table_context)
        
        # Connect signal from utility panel to control panel "users looking at function" functionality
        self._utilities_panel.connected_to_server.connect(self._update_aux_server_status)
        self._utilities_panel.server_context_change.connect(self._update_aux_server_contexts)

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
        ctx_name = self.controller.last_active_func.name or ""
        ctx_name = ctx_name[:12] + "..." if len(ctx_name) > 12 else ctx_name
        self._status_bar.showMessage(f"{ctx_name}@{hex(self.controller.last_active_func.addr)}")
        self._ctx_table.reload()
        self._update_aux_server_counts()

    def _update_aux_server_status(self, connected: bool):
        if connected:
            if self._context_info is not None:
                l.debug("Received connected signal when already connected")
                return
            self._context_info = HoverLabel()
            self._status_bar.addPermanentWidget(self._context_info)
            self._update_aux_server_counts()
        else: # not connected
            if self._context_info is None:
                l.debug("Received disconnected signal when already disconnected")
                return
            self._status_bar.removeWidget(self._context_info)
            self._context_info.deleteLater()
            self._context_info = None
            self._user_contexts = {}
    
    def _update_aux_server_contexts(self, user_contexts:dict[str,dict[str,int]]):
        """
        Updates user contexts to new provided values, then updates the
        _context_info widget with the new contexts
        """
        if self._context_info is None:
            l.error("Received updated auxiliary server context while not connected to server")
            return
        self._user_contexts = user_contexts
        self._update_aux_server_counts()

    def _update_aux_server_counts(self):
        if self._context_info is None:
            l.error("Trying to update counts while not connected to server")
            return
        if self.controller.last_active_func is None:
            # We are not looking at a function, but we do want to update the count
            self._context_info.setText(str(0))
            return
        
        curr_addr = self.controller.last_active_func.addr
        users = []
        for user, context_info in self._user_contexts.items():
            if context_info["func_addr"] == curr_addr:
                users.append(user)

        self._context_info.setText(str(len(users)))
        self._context_info.set_tooltip("\n".join(users))


    def _update_table_data(self, states):

        for _, table in self.tables.items():
            table.update_table(states)

        self._ctx_table.update_table(states)
