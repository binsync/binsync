import os
from functools import wraps
from typing import Optional, Iterable

from binaryninjaui import (
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja import PluginCommand, BinaryView
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon
from binaryninja.binaryview import BinaryDataNotification
import binsync
from binsync.data import Patch, Function, Comment

from .ui import find_main_window, BinjaDockWidget
from .config_dialog import ConfigDialog
from .control_panel import ControlPanelDialog


def instance():
    main_window = find_main_window()
    try:
        dock = [x for x in main_window.children() if isinstance(x, BinjaDockWidget)][0]
    except:
        dock = BinjaDockWidget()
    return dock


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if not self.check_client():
            raise ValueError("Please connect to a repo first.")
        return f(self, *args, **kwargs)
    return initcheck


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

        self.control_panel = None  # type: callable

        self.curr_bv = None  # type: Optional[BinaryView]
        self.curr_func_addr = None  # type: Optional[int]

    def connect(self, user, path, init_repo):
        self._client = binsync.Client(user, path, init_repo=init_repo)
        if self.control_panel is not None:
            self.control_panel.reload()

    def check_client(self):
        if self._client is None:
            show_message_box(
                "BinSync client does not exist",
                "You haven't connected to a binsync repo. Please connect to a binsync repo first.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )
            return False
        return True

    def mark_as_current_function(self, bv, bn_func):
        self.curr_bv = bv
        self.curr_func_addr = bn_func.start
        self.control_panel.reload()

    def current_function(self) -> Optional[Function]:
        if self.curr_bv is None:
            return None
        if self.curr_func_addr is None:
            return None
        return self.curr_bv.get_function_at(self.curr_func_addr)

    @init_checker
    def users(self):
        return self._client.users()

    @init_checker
    def push_function(self, bv, bn_func):
        # Push function
        func = binsync.data.Function(
            int(bn_func.start)
        )  # force conversion from long to int
        func.name = bn_func.name
        self._client.get_state().set_function(func)

        # Push comments
        comments = bn_func.comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            self._client.get_state().set_comment(comm_addr, comment)

        # TODO: Fixme
        self._client.save_state()

    @init_checker
    def push_patch(self, patch):
        self._client.get_state().set_patch(patch.offset, patch)
        self._client.save_state()

    @init_checker
    def pull_function(self, bn_func, user: Optional[str]=None) -> Optional[Function]:
        """
        Pull a function downwards.

        :param bv:
        :param bn_func:
        :param user:
        :return:
        """
        state = self._client.get_state(user=user)

        # pull function
        try:
            func = state.get_function(int(bn_func.start))
            return func
        except KeyError:
            return None

    @init_checker
    def fill_function(self, bn_func: binaryninja.function.Function, user: Optional[str]=None):
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """

        _func = self.pull_function(bn_func, user=user)
        if _func is None:
            return

        # name
        bn_func.name = _func.name
        # comments
        for _, ins_addr in bn_func.instructions:
            _comment = self.pull_comment(ins_addr, user=user)
            if _comment is not None:
                bn_func.set_comment_at(ins_addr, _comment)

    @init_checker
    def pull_comment(self, addr, user: Optional[str]=None) -> Optional[str]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        state = self._client.get_state(user=user)
        try:
            return state.get_comment(addr)
        except KeyError:
            return None

    @init_checker
    def pull_comments(self, start_addr, end_addr: Optional[int]=None,
                      user: Optional[str]=None) -> Optional[Iterable[str]]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        state = self._client.get_state(user=user)
        return state.get_comments(start_addr, end_addr=end_addr)


controller = BinsyncController()


def launch_binsync_configure(*args):
    d = ConfigDialog(controller)
    d.exec_()


def open_control_panel(*args):
    d = ControlPanelDialog(controller)
    d.show()


class PatchDataNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
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
        super().__init__()
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
UIActionHandler.globalActions().bindAction(
    "Configure BinSync...", UIAction(launch_binsync_configure)
)
Menu.mainMenu("Tools").addAction("Configure BinSync...", "BinSync")

UIAction.registerAction("Open BinSync control panel")
UIActionHandler.globalActions().bindAction(
    "Open BinSync control panel", UIAction(open_control_panel)
)
Menu.mainMenu("Tools").addAction("Open BinSync control panel", "BinSync")

PluginCommand.register_for_function(
    "BinSync: Mark current", "Mark as the current function in BinSync", controller.mark_as_current_function,
)
PluginCommand.register_for_function(
    "Push function upwards", "Push function upwards", controller.push_function
)
# TODO how can we avoid having users to click on this menu option?
PluginCommand.register(
    "Start Sharing Patches", "Start Sharing Patches", start_patch_monitor
)
PluginCommand.register(
    "Start Sharing Functions", "Start Sharing Functions", start_function_monitor
)
