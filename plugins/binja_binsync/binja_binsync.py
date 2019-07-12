
import os

from binaryninjaui import DockHandler, DockContextHandler, UIAction, UIActionHandler, Menu
from binaryninja import PluginCommand
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon
from binaryninja.binaryview import BinaryDataNotification
import binsync
from binsync.data import Patch
from PySide2.QtWidgets import (QDockWidget, QWidget, QApplication, QMenu, QMainWindow, QTabWidget, QMenuBar, QDialog,
    QVBoxLayout, QLabel, QLineEdit, QHBoxLayout, QPushButton, QMessageBox, QGroupBox, QCheckBox)
from PySide2.QtCore import Qt

# Some code is derived from https://github.com/NOPDev/BinjaDock/tree/master/defunct
# Thanks @NOPDev

def find_main_window():
    main_window = None
    for x in QApplication.allWidgets():
        if not isinstance(x, QDockWidget):
            continue
        main_window = x.parent()
        if isinstance(main_window, (QMainWindow, QWidget)):
            break
        else:
            main_window = None

    if main_window is None:
        # oops cannot find the main window
        raise Exception("Main window is not found.")
    return main_window

def instance():
    main_window = find_main_window()
    try:
        dock = [x for x in main_window.children() if isinstance(x, BinjaDockWidget)][0]
    except:
        dock = BinjaDockWidget()
    return dock


class BinjaWidgetBase:
    def __init__(self):
        self._main_window = None
        self._menu_bar = None
        self._tool_menu = None

    @property
    def main_window(self):
        if self._main_window is None:
            self._main_window = find_main_window()
        return self._main_window

    @property
    def menu_bar(self):
        if self._menu_bar is None:
            self._menu_bar = next(iter(x for x in self._main_window.children() if isinstance(x, QMenuBar)))
        return self._menu_bar

    @property
    def tool_menu(self):
        if self._tool_menu is None:
            self._tool_menu = next(iter(x for x in self._menu_bar.children()
                                        if isinstance(x, QMenu) and x.title() == u'Tools'))
        return self._tool_menu

    def add_tool_menu_action(self, name, func):
        self.tool_menu.addAction(name, func)


class BinjaDockWidget(QDockWidget):
    def __init__(self, *args):
        super(BinjaDockWidget, self).__init__(*args)

        self.base = BinjaWidgetBase()

        self.base.add_tool_menu_action('Toggle plugin dock', self.toggle)
        # self._main_window.addDockWidget(Qt.RightDockWidgetArea, self)
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.East)
        self.setWidget(self._tabs)

        # self.hide()
        self.show()

    def toggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()


class BinjaWidget(QWidget):
    def __init__(self, tabname):
        super(BinjaWidget, self).__init__()
        # self._core = instance()
        # self._core.addTabWidget(self, tabname)


class BinsyncDialog(QDialog):
    def __init__(self, controller):
        super(BinsyncDialog, self).__init__()

        self._w = None
        self._controller = controller

        self.setWindowTitle("BinSync")

        self._init_widgets()

    def _init_widgets(self):
        self._w = BinsyncWidget(self._controller, dialog=self)

        layout = QVBoxLayout()
        layout.addWidget(self._w)

        self.setLayout(layout)


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

    def connect(self, user, path, init_repo):
        self._client = binsync.Client(user, path, init_repo=init_repo)

    def _check_client(self):
        if self._client is None:
            show_message_box(
                "BinSync client does not exist",
                "You haven't connected to a binsync repo. Please connect to a binsync repo first.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )
            return False
        return True

    def push_function(self, bv, bn_func):
        if not self._check_client():
            return

        # Push function
        func = binsync.data.Function(int(bn_func.start))  # force conversion from long to int
        func.name = bn_func.name
        self._client.get_state().set_function(func)

        # Push comments
        comments = bn_func.comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            self._client.get_state().set_comment(comm_addr, comment)

        # TODO: Fixme
        self._client.save_state()

    def push_patch(self, patch):
        if not self._check_client():
            return
        self._client.get_state().set_patch(patch.offset, patch)
        self._client.save_state()


class BinsyncWidget(BinjaWidget):
    def __init__(self, controller, dialog):
        super(BinsyncWidget, self).__init__("BinSync")

        self._funcaddr_edit = None  # type: QLineEdit
        self._controller = controller
        self._dialog = dialog

        self._init_widgets()

    def _init_widgets(self):

        #
        # Config
        #

        # user label
        user_label = QLabel(self)
        user_label.setText("User name")

        self._user_edit = QLineEdit(self)
        self._user_edit.setText("user0_binja")

        user_layout = QHBoxLayout()
        user_layout.addWidget(user_label)
        user_layout.addWidget(self._user_edit)

        # binsync label
        binsync_label = QLabel(self)
        binsync_label.setText("Git repo")

        # repo path
        self._repo_edit = QLineEdit(self)

        # layout
        repo_layout = QHBoxLayout()
        repo_layout.addWidget(binsync_label)
        repo_layout.addWidget(self._repo_edit)

        checkbox_layout = QHBoxLayout()
        init_repo_label = QLabel(self)
        init_repo_label.setText("Initialize repo")
        checkbox_layout.addWidget(init_repo_label)
        self._initrepo_checkbox = QCheckBox(self)
        self._initrepo_checkbox.setToolTip("I'm the first user of this sync repo and I'd like to initialize it as a new repo.")
        self._initrepo_checkbox.setChecked(False)
        self._initrepo_checkbox.setEnabled(True)
        checkbox_layout.addWidget(self._initrepo_checkbox)

        # buttons
        connect_button = QPushButton(self)
        connect_button.setText("Connect")
        connect_button.clicked.connect(self._on_connect_clicked)
        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(connect_button)
        buttons_layout.addWidget(cancel_button)

        config_box = QGroupBox()
        config_box.setTitle("Configuration")
        config_layout = QVBoxLayout()
        config_layout.addLayout(user_layout)
        config_layout.addLayout(repo_layout)
        config_layout.addLayout(checkbox_layout)
        config_layout.addLayout(buttons_layout)
        config_box.setLayout(config_layout)

        # main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(config_box)

        self.setLayout(main_layout)

    def _on_connect_clicked(self):
        user = self._user_edit.text()
        path = self._repo_edit.text()
        init_repo = self._initrepo_checkbox.isChecked()

        if not user:
            QMessageBox(self).critical(None, "Invalid user name",
                                       "User name cannot be empty."
                                       )
            return

        if not os.path.isdir(path):
            QMessageBox(self).critical(None, "Repo does not exist",
                                       "The specified sync repo does not exist."
                                       )
            return

        # TODO: Add a user ID to angr management
        self._controller.connect(user, path, init_repo)

        if self._dialog is not None:
            self._dialog.close()
        else:
            self.close()

    def _on_cancel_clicked(self):
        if self._dialog is not None:
            self._dialog.close()
        else:
            self.close()


controller = BinsyncController()

def launch_binsync_configure(*args):
    d = BinsyncDialog(controller)
    d.exec_()


class PatchDataNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        self._view = view
        self._controller = controller
        self._patch_number = 0

    def data_written(self, view, offset, length):
        # TODO think about the naming

        file_offset = offset - view.start
        obj_name = os.path.basename(view.file.original_filename)
        patch = Patch(obj_name, file_offset, view.read(offset, length))
        self._patch_number += 1
        self._controller.push_patch(patch)


class EditFunctionNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        self._view = view
        self._controller = controller

    def function_updated(self, view, func):
        self._controller.push_function(view, func)


def start_patch_monitor(view):
    notification = PatchDataNotification(view, controller)
    view.register_notification(notification)

def start_function_monitor(view):
    notification = EditFunctionNotification(view, controller)
    view.register_notification(notification)


UIAction.registerAction("Configure BinSync...")
UIActionHandler.globalActions().bindAction("Configure BinSync...", UIAction(launch_binsync_configure))
Menu.mainMenu("Tools").addAction("Configure BinSync...", "BinSync")
PluginCommand.register_for_function("Push function upwards", "Push function upwards", controller.push_function)
# TODO how can we avoid having users to click on this menu option?
PluginCommand.register("Start Sharing Patches", "Start Sharing Patches", start_patch_monitor)
PluginCommand.register("Start Sharing Functions", "Start Sharing Functions", start_function_monitor)
