import logging

from binsync.ui.force_push.panels.functions_table import QFunctionTable
from binsync.ui.force_push.panels.globals_table import QGlobalsTable
from binsync.ui.force_push.panels.segments_table import QSegmentTable
from libbs.api.utils import progress_bar
from libbs.ui.qt_objects import (
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QCheckBox,
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

        # add the functions tab
        self._func_table = QFunctionTable(self.controller, use_cache=True, exclude_defaults=True, use_decompilation=False)
        self._exclude_defaults_btn = QCheckBox(
            f'Exclude default named functions "{self.controller.deci.default_func_prefix}"'
        )
        self._exclude_defaults_btn.setChecked(True)
        self._exclude_defaults_btn.stateChanged.connect(self._exclude_defaults_changed)
        self._use_dec_btn = QCheckBox("Use decompilation (slow)")
        self._use_dec_btn.setChecked(False)
        self._use_dec_btn.stateChanged.connect(self._use_decompilation_changed)
        self._func_tab = QWidget()
        self._func_tab_layout = QVBoxLayout()
        self._func_tab_layout.addWidget(self._exclude_defaults_btn)
        self._func_tab_layout.addWidget(self._use_dec_btn)
        self._func_tab_layout.addWidget(self._func_table)
        self._func_tab.setLayout(self._func_tab_layout)

        # add globals tab
        self._global_table = QGlobalsTable(self.controller)

        # add segments tab
        self._segment_table = QSegmentTable(self.controller)

        self.tabView.addTab(self._func_tab, "Functions")
        self.tabView.addTab(self._global_table, "Globals")
        self.tabView.addTab(self._segment_table, "Segments")

        self.tables.update({
            "functions": self._func_table,
            "globals": self._global_table,
            "segments": self._segment_table
        })

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabView)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _exclude_defaults_changed(self, state):
        self._func_table.table.model.exclude_defaults = bool(state)
        self._func_table.update_table()

    def _use_decompilation_changed(self, state):
        self._func_table.table.use_decompilation = bool(state)

    def _update_table_data(self):
        for _, table in progress_bar(self.tables.items(), gui=True, desc="Loading functions, globals, and segments..."):
            table.update_table()
