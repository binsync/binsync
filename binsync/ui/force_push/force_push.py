import logging

from binsync.ui.force_push.panels.functions_table import QFunctionTable
from binsync.ui.force_push.panels.globals_table import QGlobalsTable
from libbs.api.utils import progress_bar
from libbs.ui.qt_objects import (
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
        self._update_table_data()

    def _init_widgets(self):
        # tabs for panel_tabs
        self.tabView = QTabWidget()
        self.tabView.setContentsMargins(0, 0, 0, 0)

        # add panel_tabs to tabs
        self._func_table = QFunctionTable(self.controller)
        self._global_table = QGlobalsTable(self.controller)

        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._global_table, "Globals")

        self.tables.update({
            "functions": self._func_table,
            "globals": self._global_table
        })

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabView)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _update_table_data(self):
        for _, table in progress_bar(self.tables.items(), gui=True, desc="Loading functions and globals..."):
            table.update_table()
