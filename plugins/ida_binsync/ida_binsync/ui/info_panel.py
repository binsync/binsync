from PyQt5.QtWidgets import QVBoxLayout, QGroupBox, QMessageBox, QDialog, QWidget
from PyQt5.QtCore import Qt
import sip

import idc
import idaapi
import idautils

from .info_table import QInfoTable


class InfoPanelDialog(QDialog):
    def __init__(self, controller, parent=None):
        super(InfoPanelDialog, self).__init__(parent=parent)

        self._w = None
        self._controller = controller

        self.setWindowTitle("BinSync Control Panel")
        
        self._init_widgets()

        # always on top
        self.setWindowFlag(Qt.WindowStaysOnTopHint)

    def _init_widgets(self):
        self._w = InfoPanel(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class InfoPanelViewWrapper(object):

    NAME = "BinSync: Control Panel"

    def __init__(self, controller):
        
        # create a dockable view
        self.twidget = idaapi.create_empty_widget(InfoPanelViewWrapper.NAME)
        self.widget = sip.wrapinstance(int(self.twidget), QWidget)
        self.widget.name = InfoPanelViewWrapper.NAME

        self._controller = controller
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

        self._controller = controller
        self._dialog = dialog

        self._info_table = None  # type: QInfoTable

        self._init_widgets()

        self.width_hint = 250

        # register callback
        self._controller.control_panel = self

        self.reload()

    def reload(self):
        # update users
        if self._controller is not None and self._controller.check_client():
            self._info_table.update_users(self._controller.users())

    def closeEvent(self, event):
        if self._controller is not None:
            self._controller.client_init_callback = None

    #
    # Private methods
    #

    def _init_widgets(self):

        self._info_table = QInfoTable(self._controller)

        team_box = QGroupBox(self)
        team_box.setTitle("Binsync Changed Function\n")

        team_layout = QVBoxLayout()
        team_layout.addWidget(self._info_table)    # stretch=1 optional
        # team_layout.addWidget(actions_box)
        team_box.setLayout(team_layout)

        main_layout = QVBoxLayout()
        #main_layout.addWidget(status_box)
        main_layout.addWidget(team_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)

    def _on_pullpatches_clicked(self):

        # which user?
        u = self._info_table.selected_user()
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
        self._info_table.update_users(self.workspace.instance.sync.users)
