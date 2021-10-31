import datetime

from . import ui_version
if ui_version == "PySide2":
    from PySide2.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget
elif ui_version == "PySide6":
    from PySide6.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget
else:
    from PyQt5.QtWidgets import QVBoxLayout, QGroupBox, QWidget, QLabel, QTabWidget, QTableWidget

from .tables.functions_table import QFunctionTable


class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super(ControlPanel, self).__init__(parent)
        self.controller = controller

        self._init_widgets()

        # register callback
        self.controller.control_panel = self

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
        self._user_table = QTableWidget()
        self._func_table = QFunctionTable(self.controller)
        self._struct_table = QTableWidget()
        self._autosync_table = QTableWidget()

        self.tabView.addTab(self._user_table, "Context")
        self.tabView.addTab(self._func_table, "Functions")
        self.tabView.addTab(self._struct_table, "Globals")
        self.tabView.addTab(self._autosync_table, "Activity")

        control_layout.addWidget(self.tabView)
        control_box.setLayout(control_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(control_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)

    def _update_tables(self):
        if self.controller.client.has_remote:
            self.controller.client.init_remote()

        self._func_table.update_table()

