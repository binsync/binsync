from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QMessageBox, QDialog
from PySide2.QtCore import Qt

from .ui import BinjaWidget, BinjaDockWidget
from .team_table import QTeamTable
from .status_table import QStatusTable


class ControlPanelDialog(QDialog):
    def __init__(self, controller):
        super().__init__()

        self._w = None
        self._controller = controller

        self.setWindowTitle("BinSync Control Panel")
        self._init_widgets()

        # always on top
        self.setWindowFlag(Qt.WindowStaysOnTopHint)

    def _init_widgets(self):
        self._w = ControlPanel(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class ControlPanelDockWidget(BinjaDockWidget):
    def __init__(self, controller, parent=None, name=None, data=None):
        super().__init__(name, parent=parent)

        self.data = data
        self._w = None
        self._controller = controller

        self._init_widgets()

    def _init_widgets(self):
        self._w = ControlPanel(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class ControlPanel(BinjaWidget):
    def __init__(self, controller, dialog):
        super().__init__("BinSync Control Panel")

        self._controller = controller
        self._dialog = dialog

        self._status_table = None  # type: QStatusTable
        self._team_table = None  # type: QUserTable

        self._init_widgets()

        self.width_hint = 250

        # register callback
        self._controller.control_panel = self

        self.reload()

    def reload(self):
        # update status
        self._status_table.status = "ready"
        curr_func = self._controller.current_function()
        if curr_func is not None:
            self._status_table.current_function = curr_func.name
        self._status_table.reload()
        # update users
        if self._controller is not None and self._controller.check_client():
            self._team_table.update_users(self._controller.users())

    def closeEvent(self, event):
        if self._controller is not None:
            self._controller.client_init_callback = None

    #
    # Private methods
    #

    def _init_widgets(self):

        # status
        status_box = QGroupBox(self)
        status_box.setTitle("Status")

        self._status_table = QStatusTable(self._controller)
        self._status_table.status = "ready"

        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_table)

        status_box.setLayout(status_layout)

        # table

        self._team_table = QTeamTable(self._controller)
        team_box = QGroupBox(self)
        team_box.setTitle("Team")

        # operations

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

        team_layout = QVBoxLayout()
        team_layout.addWidget(self._team_table)
        team_layout.addWidget(actions_box)
        team_box.setLayout(team_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(team_box)

        self.setLayout(main_layout)

    #
    # Event callbacks
    #

    def _on_pullfunc_clicked(self):

        current_function = self._controller.current_function()
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "Please set the current function first.")
            return

        # which user?
        u = self._team_table.selected_user()
        if u is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        self._controller.fill_function(current_function, user=u)

    def _on_pushfunc_clicked(self):

        current_function = self._controller.current_function()
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "Please set the current function first.")
            return

        func = current_function

        with self._controller.state_ctx(locked=True) as state:

            # function name
            self._controller.push_function(func, state=state)

            # comments
            self._controller.remove_all_comments(func, state=state)
            self._controller.push_comments(func.comments, state=state)

            # stack variables
            self._controller.push_stack_variables(func, state=state)

    def _on_pullpatches_clicked(self):

        # which user?
        u = self._team_table.selected_user()
        if u is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        kb = self.workspace.instance.project.kb
        # currently we assume all patches are against the main object
        main_object = self.workspace.instance.project.loader.main_object
        patches = kb.sync.pull_patches(user=u)

        patch_added = False
        for patch in patches:
            addr = main_object.mapped_base + patch.offset
            kb.patches.add_patch(addr, patch.new_bytes)
            patch_added = True

        if patch_added:
            # trigger a refresh
            self.workspace.instance.patches.am_event()

            # re-generate the CFG
            # TODO: CFG refinement
            self.workspace.instance.generate_cfg()

    def _update_users(self):
        self._team_table.update_users(self.workspace.instance.sync.users)
