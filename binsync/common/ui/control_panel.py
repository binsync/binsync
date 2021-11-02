import datetime

from . import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget
    from PySide2.QtCore import Signal
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget
    from PySide2.QtCore import Signal
else:
    from PyQt5.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget
    from PyQt5.QtCore import pyqtSignal as Signal

from .tables.functions_table import QFunctionTable
from .tables.activiy_table import QActivityTable
from .tables.ctx_table import QCTXTable
from .tables.globals_table import QGlobalsTable


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
        self.update_callback = self.update_ready.emit
        self.controller.ui_callback = self.update_callback

        self.ctx_change.connect(self._update_ctx)
        self.ctx_change_callback = self.ctx_change.emit
        self.controller.ctx_change_callback = self.ctx_change_callback

    def reload(self):
        # check if connected
        if self.controller and self.controller.check_client():
            self._update_tables()

        # update status
        status = self.controller.status_string() if self.controller else "Disconnected"
        self._status_label.setText(status)

    def closeEvent(self, event):
        if self.controller is not None:
            self.controller.client_init_callback = None

    def _init_widgets(self):
        # status box
        status_box = QGroupBox(self)
        status_box.setTitle("Status")
        self._status_label = QLabel(self)
        self._status_label.setText("Not Connected")
        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_label)
        status_box.setLayout(status_layout)

        # control box
        control_box = QGroupBox(self)
        control_box.setTitle("Control Panel")
        control_layout = QVBoxLayout()

        # tabs for tables
        self.tabView = QTabWidget()

        # add tables to tabs
        self._ctx_table = QCTXTable(self.controller)
        self._func_table = QFunctionTable(self.controller)
        self._global_table = QGlobalsTable(self.controller)
        self._activity_table = QActivityTable(self.controller)

        self.tabView.addTab(self._ctx_table, "Context")
        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._global_table, "Globals")
        self.tabView.addTab(self._activity_table, "Activity")

        self.tables.update({
            "context": self._ctx_table,
            "functions": self._func_table,
            "globals": self._global_table,
            "activity": self._activity_table
        })

        control_layout.addWidget(self.tabView)
        control_box.setLayout(control_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(control_box)

        self.setLayout(main_layout)

    def _update_ctx(self):
        self._ctx_table.update_table(new_ctx=self.controller.last_ctx)

    def _update_tables(self):
        if self.controller.client.has_remote:
            self.controller.client.init_remote()

        for _, table in self.tables.items():
            table.update_table()
