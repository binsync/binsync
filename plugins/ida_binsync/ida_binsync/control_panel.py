from __future__ import absolute_import

from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QPushButton, QMessageBox, QDialog, QWidget
from PyQt5.QtCore import Qt
import idc
import idaapi
import idautils
import sip

from .status_table import QStatusTable
from .team_table import QTeamTable

from . import compat


class ControlPanelDialog(QDialog):
    def __init__(self, controller, parent=None):
        super(ControlPanelDialog, self).__init__(parent=parent)

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


class ControlPanelViewWrapper(object):

    NAME = "BinSync: Control Panel"

    def __init__(self, controller):
        
        # create a dockable view
        self.twidget = idaapi.create_empty_widget(ControlPanelViewWrapper.NAME)
        self.widget = sip.wrapinstance(int(self.twidget), QWidget)
        self.widget.name = ControlPanelViewWrapper.NAME

        self._controller = controller
        self._w = None

        self._init_widgets()

    def _init_widgets(self):
        self._w = ControlPanel(self._controller, self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.widget.setLayout(layout)


class ControlPanel(QWidget):
    def __init__(self, controller, dialog, parent=None):
        super(ControlPanel, self).__init__(parent)
        
        #self.setMaximumHeight(400)
        #self.setMaximumWidth(300)

        self._controller = controller
        self._dialog = dialog

        self._team_table = None  # type: QTeamTable

        self._init_widgets()

        self.width_hint = 250

        # register callback
        self._controller.control_panel = self

        self.reload()

    def reload(self):
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

        self._team_table = QTeamTable(self._controller)

        team_box = QGroupBox(self)
        team_box.setTitle("Binsync Function Syncs\n")

        team_layout = QVBoxLayout()
        team_layout.addWidget(self._team_table)    # stretch=1 optional
        # team_layout.addWidget(actions_box)
        team_box.setLayout(team_layout)

        main_layout = QVBoxLayout()
        #main_layout.addWidget(status_box)
        main_layout.addWidget(team_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)


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
            self._controller.push_function(func, state=state)

            # comments
            comments = { }
            for start_ea, end_ea in idautils.Chunks(func.start_ea):
                for head in idautils.Heads(start_ea, end_ea):
                    cmt_0 = idc.GetCommentEx(head, 0)  # regular comment
                    cmt_1 = idc.GetCommentEx(head, 1)  # repeatable comment
                    if cmt_0 and cmt_1:
                        cmt = cmt_0 + " | " + cmt_1
                    elif cmt_0 or cmt_1:
                        cmt = cmt_0 or cmt_1
                    else:
                        cmt = None
                    if cmt:
                        comments[head] = cmt
            self._controller.remove_all_comments(func, state=state)
            self._controller.push_comments(comments, state=state)

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
