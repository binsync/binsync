from PySide2.QtWidgets import QVBoxLayout, QGroupBox, QMessageBox, QDialog, QWidget, QLabel, QComboBox, QHBoxLayout
from PySide2.QtCore import Qt

from .info_tables.func_info_table import QFuncInfoTable
from .info_tables.struct_info_table import QStructInfoTable
from .info_tables.user_info_table import QUserInfoTable
from .info_tables.autosync_info_table import QAutoSyncInfoTable
from .info_tables.cur_func_info_table import QCurFuncInfoTable
from ..controller import BinsyncController


from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QMessageBox, QDialog
from PySide2.QtCore import Qt

from .ui_tools import BinjaWidget, BinjaDockWidget


class InfoPanelDialog(QDialog):
    def __init__(self, controller):
        super().__init__()

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


class InfoPanelDockWidget(BinjaDockWidget):
    def __init__(self, controller, parent=None, name=None, data=None):
        super().__init__(name, parent=parent)

        self.data = data
        self._w = None
        self._controller = controller

        self._init_widgets()

    def _init_widgets(self):
        self._w = InfoPanel(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class InfoPanel(QWidget):
    def __init__(self, controller, dialog, parent=None):
        super(InfoPanel, self).__init__(parent)
        
        #self.setMaximumHeight(400)
        #self.setMaximumWidth(300)

        self._controller: BinsyncController = controller
        self._dialog = dialog

        # info tables
        self._user_table = None  # type: QUserInfoTable
        self._cur_func_table = None # type: QCurFuncInfoTable
        self._func_table = None  # type: QUserInfoTable
        self._struct_table = None  # type: QStructInfoTable
        self._active_table = None  # type: QTableWidget

        self._init_widgets()

        self.width_hint = 250

        # register callback
        self._controller.info_panel = self

        self.reload()

    def reload(self):
        # check if connected
        if self._active_table and self._controller and self._controller.check_client():

            # update the tables
            self._update_info_tables()

        # update status
        self._status_label.setText(self._controller.status_string())

    def reload_curr(self, users):
        self._cur_func_table.update_users(users)


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
        self.combo.addItems(["Users", "Current Function", "Functions", "Structs", "Auto-Sync"])
        self.combo.currentTextChanged.connect(self._on_combo_change)
        combo_layout.addWidget(self.combo)
        combo_box.setLayout(combo_layout)
        info_layout.addWidget(combo_box)

        #
        #   Tables
        #

        # user info table
        self._user_table = QUserInfoTable(self._controller)
        info_layout.addWidget(self._user_table)
        self._active_table = self._user_table

        # current function info table
        self._cur_func_table = QCurFuncInfoTable(self._controller)
        self._cur_func_table.hide()
        info_layout.addWidget(self._cur_func_table)

        # function info table
        self._func_table = QFuncInfoTable(self._controller)
        self._func_table.hide()
        info_layout.addWidget(self._func_table)    # stretch=1 optional

        # struct info table
        self._struct_table = QStructInfoTable(self._controller)
        self._struct_table.hide()
        info_layout.addWidget(self._struct_table)

        # auto-sync info table
        self._autosync_table = QAutoSyncInfoTable(self._controller)
        self._autosync_table.hide()
        info_layout.addWidget(self._autosync_table)

        #
        #   Actions
        #

        # pull function button
        pullfunc_btn = QPushButton(self)
        pullfunc_btn.setText("Pull func")
        pullfunc_btn.setToolTip("Pull current function from the selected user")
        pullfunc_btn.clicked.connect(self._on_pullfunc_clicked)

        # push function button
        pushfunc_btn = QPushButton()
        pushfunc_btn.setText('Push func')
        pushfunc_btn.setToolTip("Push current function to the repo")
        pushfunc_btn.clicked.connect(self._on_pushfunc_clicked)

        # pull patches button
        pullpatches_btn = QPushButton(self)
        pullpatches_btn.setText("Pull patches")
        pullpatches_btn.setToolTip("Pull all patches from the selected user")
        pullpatches_btn.clicked.connect(self._on_pullpatches_clicked)

        actions_box = QGroupBox(self)
        actions_box.setTitle("Actions")
        actions_layout = QHBoxLayout()
        actions_layout.addWidget(pullfunc_btn)
        actions_layout.addWidget(pushfunc_btn)
        actions_layout.addWidget(pullpatches_btn)
        actions_box.setLayout(actions_layout)


        #
        #   Main Layout
        #

        info_layout.addWidget(actions_box)
        info_box.setLayout(info_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(info_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)

    def _on_combo_change(self, value):
        self._hide_all_tables()
        if value == "Users":
            self._user_table.show()
            self._active_table = self._user_table
        elif value == "Current Function":
            self._cur_func_table.show()
            self._active_table = self._cur_func_table
        elif value == "Functions":
            self._func_table.show()
            self._active_table = self._func_table
        elif value == "Structs":
            self._struct_table.show()
            self._active_table = self._struct_table
        elif value == "Auto-Sync":
            self._autosync_table.show()
            self._active_table = self._autosync_table

    def _on_pushfunc_clicked(self):
        current_function = self._controller.current_function()
        if current_function is None:
            QMessageBox.critical(None, 'Error', "Please got to a function first.")
            return

        func = current_function
        with self._controller.state_ctx(locked=True) as state:

            # function name
            self._controller.push_function(func, state=state)

            # comments
            #self._controller.remove_all_comments(func, state=state)
            self._controller.push_comments(func, func.comments, state=state)

            # stack variables
            self._controller.push_stack_variables(func, state=state)

    def _on_pullfunc_clicked(self):
        current_function = self._controller.current_function()
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "Please set the current function first.")
            return

        # which user?
        username = self._cur_func_table.selected_user()
        if username is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        self._controller.fill_function(current_function, user=username)

        pass

    def _on_pullpatches_clicked(self):
        # TODO: support patches
        pass

    def _hide_all_tables(self):
        self._func_table.hide()
        self._cur_func_table.hide()
        self._struct_table.hide()
        self._user_table.hide()
        self._autosync_table.hide()

    def _update_info_tables(self):
        if self._controller.client.has_remote:
            self._controller.client.init_remote()

        users = list(self._controller.users())

        self._cur_func_table.update_users(users)
        self._user_table.update_users(users)
        self._func_table.update_users(users)
        self._struct_table.update_users(users)
        self._autosync_table.update_table()