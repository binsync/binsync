import logging

from binsync.ui.force_push.panels.functions_table import QFunctionTable
from binsync.ui.force_push.panels.globals_table import QGlobalsTable
from binsync.ui.force_push.panels.types_table import QTypesTable
from binsync.ui.force_push.panels.segments_table import QSegmentTable
from libbs.api.utils import progress_bar
from libbs.ui.qt_objects import (
    QDialog,
    QTabWidget,
    QVBoxLayout,
    Signal
)

l = logging.getLogger(__name__)

class ForcePushUI(QDialog):
    update_ready = Signal()
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller

        self.setWindowTitle("Force Push")
        self.resize(900, 650)
        self.setMinimumSize(500, 400)

        self.tables = {}
        self._init_widgets()
        self._update_table_data()

    def _init_widgets(self):
        self.tabView = QTabWidget()
        self.tabView.setContentsMargins(0, 0, 0, 0)

        self._func_table = QFunctionTable(self.controller, use_cache=True, exclude_defaults=True, use_decompilation=False)

        self._global_table = QGlobalsTable(self.controller)
        self._types_table = QTypesTable(self.controller)

        self._segment_table = QSegmentTable(self.controller)

        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._global_table, "Globals")
        self.tabView.addTab(self._types_table, "Types")
        self.tabView.addTab(self._segment_table, "Segments")

        self.tables.update({
            "functions": self._func_table,
            "globals": self._global_table,
            "types": self._types_table,
            "segments": self._segment_table
        })

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabView)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _update_table_data(self):
        for _, table in progress_bar(self.tables.items(), gui=True, desc="Loading functions, globals, and segments..."):
            table.update_table()
