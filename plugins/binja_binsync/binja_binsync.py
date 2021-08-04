import os
import re
import time
import threading
import datetime
from functools import wraps
from typing import Optional, Iterable, Dict, Any
import logging

from PySide2.QtCore import Qt
from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja import PluginCommand, BinaryView
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.binaryview import BinaryDataNotification
import binsync
from binsync import State, StateContext
from binsync.data import Patch, Function, Comment, StackVariable, StackOffsetType

from .ui import find_main_window, BinjaDockWidget, create_widget
from .config_dialog import ConfigDialog
from .control_panel import ControlPanelDialog, ControlPanelDockWidget

_l = logging.getLogger(name=__name__)


def instance():
    main_window = find_main_window()
    try:
        dock = [x for x in main_window.children() if isinstance(x, BinjaDockWidget)][0]
    except:
        dock = BinjaDockWidget("dummy")
    return dock


#
# Decorators
#

def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if not self.check_client():
            raise RuntimeError("Please connect to a repo first.")
        return f(self, *args, **kwargs)
    return initcheck


def make_state(f):
    """
    Build a writeable State instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """
    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            save_before_return = True
            state = self.client.get_state(user=user)
        else:
            save_before_return = False
        r = f(self, *args, **kwargs, state=state)
        if save_before_return:
            state.save()
        return r
    return state_check


def make_ro_state(f):
    """
    Build a read-only State instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """
    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            state = self.client.get_state(user=user)
        return f(self, *args, **kwargs, state=state)
    return state_check


#
# Controller
#


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

        self.control_panel = None

        self.curr_bv = None  # type: Optional[BinaryView]
        self.curr_func = None  # type: Optional[binaryninja.function.Function]

        # start the worker routine
        self.worker_thread = threading.Thread(target=self.worker_routine, daemon=True)
        self.worker_thread.start()

    def worker_routine(self):
        while True:
            # reload the control panel if it's registered
            if self.control_panel is not None:
                try:
                    self.control_panel.reload()
                except RuntimeError:
                    # the panel has been closed
                    self.control_panel = None

            # pull the repo every 10 seconds
            if self.check_client() and self._client.has_remote \
                    and (
                         self._client._last_pull_attempt_at is None
                         or (datetime.datetime.now() - self._client._last_pull_attempt_at).seconds > 10
                         ):
                self._client.pull()

            time.sleep(1)

    def connect(self, user, path, init_repo, ssh_agent_pid=None, ssh_auth_sock=None):
        self._client = binsync.Client(user, path, init_repo=init_repo, ssh_agent_pid=ssh_agent_pid,
                                      ssh_auth_sock=ssh_auth_sock)
        if self.control_panel is not None:
            self.control_panel.reload()

    def check_client(self, message_box=False):
        if self._client is None:
            if message_box:
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
        self.curr_func = bn_func
        self.control_panel.reload()

    def current_function(self, message_box=False) -> Optional[Function]:
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            if message_box:
                show_message_box(
                    "UI contexts not found",
                    "No UI context is available. Please open a binary first.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon,
                )
            return
        ctx = all_contexts[0]
        handler = ctx.contentActionHandler()
        if handler is None:
            if message_box:
                show_message_box(
                    "Action handler not found",
                    "No action handler is available. Please open a binary first.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon,
                )
            return
        actionContext = handler.actionContext()
        func = actionContext.function
        if func is None:
            if message_box:
                show_message_box(
                    "No function is in selection",
                    "Please navigate to a function in the disassembly view.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon,
                )
            return None

        return func

    def state_ctx(self, user=None, version=None, locked=False) -> StateContext:
        return self._client.state_ctx(user=user, version=version, locked=locked)

    @init_checker
    def status(self) -> Dict[str,Any]:
        return self._client.status()

    @init_checker
    def users(self):
        return self._client.users()

    @init_checker
    @make_state
    def push_function(self, bn_func: binaryninja.function.Function, state: State=None):
        # Push function
        func = binsync.data.Function(
            int(bn_func.start)
        )  # force conversion from long to int
        func.name = bn_func.name
        state.set_function(func)

    @init_checker
    @make_state
    def push_patch(self, patch, state: State=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state
    def push_stack_variable(self, bn_func: binaryninja.Function, stack_var: binaryninja.function.Variable,
                            state: State=None):
        if stack_var.source_type != VariableSourceType.StackVariableSourceType:
            raise TypeError("Unexpected source type %s of the variable %r." % (stack_var.source_type, stack_var))

        type_str = stack_var.type.get_string_before_name()
        size = stack_var.type.width
        v = StackVariable(stack_var.storage,
                          StackOffsetType.BINJA,
                          stack_var.name,
                          type_str,
                          size,
                          bn_func.start)
        state.set_stack_variable(bn_func.start, stack_var.storage, v)

    @init_checker
    @make_state
    def push_stack_variables(self, bn_func, state: State=None):
        for stack_var in bn_func.stack_layout:
            # ignore all unnamed variables
            # TODO: Do not ignore re-typed but unnamed variables
            if re.match(r"var_\d+[_\d+]{0,1}", stack_var.name) \
                    or stack_var.name in {
                '__saved_rbp', '__return_addr',
            }:
                continue
            if not stack_var.source_type == VariableSourceType.StackVariableSourceType:
                continue
            self.push_stack_variable(bn_func, stack_var, state=state)

    @init_checker
    @make_ro_state
    def pull_stack_variables(self, bn_func, user: Optional[str]=None, state: State=None) -> Dict[int,StackVariable]:
        try:
            return dict(state.get_stack_variables(bn_func.start))
        except KeyError:
            return { }

    @init_checker
    @make_ro_state
    def pull_stack_variable(self, bn_func, offset: int, user: Optional[str]=None, state: State=None) -> StackVariable:
        return state.get_stack_variable(bn_func.start, offset)

    @init_checker
    @make_ro_state
    def pull_function(self, bn_func, user: Optional[str]=None, state: State=None) -> Optional[Function]:
        """
        Pull a function downwards.

        :param bv:
        :param bn_func:
        :param user:
        :return:
        """

        # pull function
        try:
            func = state.get_function(int(bn_func.start))
            return func
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def fill_function(self, bn_func: binaryninja.function.Function, user: Optional[str]=None,
                      state: State=None) -> None:
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """

        _func = self.pull_function(bn_func, user=user, state=state)
        if _func is None:
            return

        # name
        bn_func.name = _func.name

        # comments
        for _, ins_addr in bn_func.instructions:
            _comment = self.pull_comment(ins_addr, user=user, state=state)
            if _comment is not None:
                bn_func.set_comment_at(ins_addr, _comment)

        # stack variables
        existing_stack_vars: Dict[int,Any] = dict((v.storage, v) for v in bn_func.stack_layout
                                                  if v.source_type == VariableSourceType.StackVariableSourceType)
        for offset, stack_var in self.pull_stack_variables(bn_func, user=user, state=state).items():
            bn_offset = stack_var.get_offset(StackOffsetType.BINJA)
            # skip if this variable already exists
            type_, _ = bn_func.view.parse_type_string(stack_var.type)
            if bn_offset in existing_stack_vars \
                    and existing_stack_vars[bn_offset].name == stack_var.name \
                    and existing_stack_vars[bn_offset].type == type_:
                continue
            bn_func.create_user_stack_var(bn_offset, type_, stack_var.name)

    @init_checker
    @make_state
    def remove_all_comments(self, bn_func: binaryninja.function.Function, user: Optional[str]=None,
                            state: State=None) -> None:
        for _, ins_addr in bn_func.instructions:
            if ins_addr in state.comments:
                state.remove_comment(ins_addr)

    @init_checker
    @make_state
    def push_comments(self, comments: Dict[int,str], state: State=None) -> None:
        # Push comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            state.set_comment(comm_addr, comment)

    @init_checker
    @make_ro_state
    def pull_comment(self, addr, user: Optional[str]=None, state: State=None) -> Optional[str]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        try:
            return state.get_comment(addr)
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_comments(self, start_addr, end_addr: Optional[int]=None,
                      user: Optional[str]=None, state: State=None) -> Optional[Iterable[str]]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        return state.get_comments(start_addr, end_addr=end_addr)


controller = BinsyncController()


class CurrentFunctionNotification(BinaryDataNotification):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller

    def function_update_requested(self, view, func):
        print("function_update_requested", view, func)
        self.controller.mark_as_current_function(view, func)

    def function_updated(self, view, func):
        print("function_updated", view, func)
        self.controller.mark_as_current_function(view, func)

    def symbol_added(self, view, sym):
        print(view, sym)

    def symbol_updated(self, view, sym):
        print(view, sym)

    def symbol_removed(self, view, sym):
        print(view, sym)


def launch_binsync_configure(context):

    if context.binaryView is None:
        show_message_box(
            "No binary is loaded",
            "There is no Binary View available. Please open a binary in Binary Ninja first.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    d = ConfigDialog(controller)
    d.exec_()

    # register a notification to get current functions
    # TODO: This is a bad idea since more than one functions might be updated when editing one function :/
    # notification = CurrentFunctionNotification(controller)
    # context.binaryView.register_notification(notification)


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
        self._controller.push_function(func)


def start_patch_monitor(view):
    notification = PatchDataNotification(view, controller)
    view.register_notification(notification)


def start_function_monitor(view):
    notification = EditFunctionNotification(view, controller)
    view.register_notification(notification)


configure_binsync_id = "BinSync: Configure"
UIAction.registerAction(configure_binsync_id)
UIActionHandler.globalActions().bindAction(
    configure_binsync_id, UIAction(launch_binsync_configure)
)
Menu.mainMenu("Tools").addAction(configure_binsync_id, "BinSync")

open_control_panel_id = "BinSync: Open control panel"
UIAction.registerAction(open_control_panel_id)
UIActionHandler.globalActions().bindAction(
    open_control_panel_id, UIAction(open_control_panel)
)
Menu.mainMenu("Tools").addAction(open_control_panel_id, "BinSync")

# register the control panel dock widget
dock_handler = DockHandler.getActiveDockHandler()
dock_handler.addDockWidget(
    "BinSync: Control Panel",
    lambda n,p,d: create_widget(ControlPanelDockWidget, n, p, d, controller),
    Qt.RightDockWidgetArea,
    Qt.Vertical,
    True
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
