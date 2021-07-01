from PyQt5.QtWidgets import QVBoxLayout, QGroupBox, QMessageBox, QDialog, QWidget, QLabel, QComboBox, QHBoxLayout
from PyQt5.QtCore import Qt
import sip

import idaapi

from .info_tables.func_info_table import QFuncInfoTable
from .info_tables.struct_info_table import QStructInfoTable
from ..controller import BinsyncController


class InfoPanelDialog(QDialog):
    def __init__(self, controller, parent=None):
        super(InfoPanelDialog, self).__init__(parent=parent)

        self._w = None
        self._controller = controller

        self.setWindowTitle("BinSync Info Panel")
        
        self._init_widgets()

        # always on top
        self.setWindowFlag(Qt.WindowStaysOnTopHint)

    def _init_widgets(self):
        self._w = InfoPanel(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class InfoPanelViewWrapper(object):

    NAME = "BinSync: Info Panel"

    def __init__(self, controller):
        
        # create a dockable view
        self.twidget = idaapi.create_empty_widget(InfoPanelViewWrapper.NAME)
        self.widget = sip.wrapinstance(int(self.twidget), QWidget)
        self.widget.name = InfoPanelViewWrapper.NAME
        self.width_hint = 250

        self._controller: BinsyncController = controller
        self._w = None

        self._init_widgets()

    def _init_widgets(self):
        self._w = InfoPanel(self._controller, self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.widget.setLayout(layout)


class InfoPanel(QWidget):
    def __init__(self, controller, dialog, parent=None):
        super(InfoPanel, self).__init__(parent)
        
        #self.setMaximumHeight(400)
        #self.setMaximumWidth(300)

        self._controller: BinsyncController = controller
        self._dialog = dialog

        # info tables
        self._func_table = None  # type: QFuncInfoTable
        self._struct_table = None  # type: QStructInfoTable
        self._active_table = None  # type: QTableWidget

        self._init_widgets()

        self.width_hint = 250

        # register callback
        self._controller.info_panel = self

        self.reload()

    def reload(self):
        # check if connected
        if self._active_table is not None and self._controller is not None and self._controller.check_client():
            # update status
            self._status_label.setText("Connected")
            self._active_table.update_users(self._controller.users())

            # update the tables
            self._update_info_tables()
        else:
            self._status_label.setText("Disconnected")

    def closeEvent(self, event):
        if self._controller is not None:
            self._controller.client_init_callback = None

    #
    # Private methods
    #

    def _init_widgets(self):

        # status box
        status_box = QGroupBox(self)
        status_box.setTitle("Status")
        self._status_label = QLabel(self)
        self._status_label.setText("Not Connected")
        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_label)
        status_box.setLayout(status_layout)

        # info box
        info_box = QGroupBox(self)
        info_box.setTitle("Info Table")
        info_layout = QVBoxLayout()

        # table selector
        combo_box = QGroupBox(self)
        combo_layout = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.addItems(["Functions", "Structs"])
        self.combo.currentTextChanged.connect(self._on_combo_change)
        combo_layout.addWidget(self.combo)
        combo_box.setLayout(combo_layout)
        info_layout.addWidget(combo_box)

        # function info table
        self._func_table = QFuncInfoTable(self._controller)
        info_layout.addWidget(self._func_table)    # stretch=1 optional
        self._active_table = self._func_table

        # struct info table
        self._struct_table = QStructInfoTable(self._controller)
        self._struct_table.hide()
        info_layout.addWidget(self._struct_table)

        info_box.setLayout(info_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(info_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)

    def _on_combo_change(self, value):
        self._hide_all_tables()
        if value == "Functions":
            self._func_table.show()
            self._active_table = self._func_table
        elif value == "Structs":
            self._struct_table.show()
            self._active_table = self._struct_table

    def _hide_all_tables(self):
        self._func_table.hide()
        self._struct_table.hide()

    def _update_info_tables(self):
        self._controller.client.init_remote()
        self._active_table.update_users(self._controller.users())
