# ----------------------------------------------------------------------------
# This file contains the BinSyncController class which acts as the the
# bridge between the plugin UI and direct calls to the binsync client found in
# the core of binsync. In the controller, you will find code used to make
# pushes and pulls of user changes.
#
# You will also notice that the BinSyncController runs two extra threads in
# it:
#   1. BinSync "git pulling" thread to constantly get changes from others
#   2. Command Routine to get hooked changes to IDA attributes
#
# The second point is more complicated because it acts as the queue of
# runnable actions that are queued from inside the hooks.py file.
# Essentially, every change that happens in IDA from the main user triggers
# a hook which will push an action to be preformed onto the command queue;
# Causing a "git push" on every change.
#
# ----------------------------------------------------------------------------

from functools import wraps
import re
import threading
import time
import datetime
import logging
from typing import Dict, List, Tuple, Optional, Iterable, Any
from collections import OrderedDict, defaultdict

from PySide2.QtWidgets import QDialog, QMessageBox

from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType

import binsync
from binsync import Client, ConnectionWarnings, StateContext, State
from binsync.data import StackVariable, StackOffsetType, Function, Struct, Comment

_l = logging.getLogger(name=__name__)


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
            state = self.client.get_state(user=user)
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
            state.save()
        else:
            kwargs['state'] = state
            r = f(self, *args, **kwargs)

        # try:
        #    if isinstance(args[0], int):
        #        self._update_function_name_if_none(args[0], user=user, state=state)
        # except Exception:
        #    print(f"[BinSync]: failed to auto set function name for {hex(args[0])}.")
        #    pass

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
        kwargs['state'] = state
        kwargs['user'] = user
        return f(self, *args, **kwargs)

    return state_check


#
#   Wrapper Classes
#


class SyncControlStatus:
    CONNECTED = 0
    CONNECTED_NO_REMOTE = 1
    DISCONNECTED = 2


#
#   Controller
#

class BinsyncController:
    def __init__(self):
        self.client = None  # type: binsync.Client

        # === UI update things ===
        self.info_panel = None
        self._last_reload = time.time()

        # start the pull routine
        self.pull_thread = threading.Thread(target=self.pull_routine)
        self.pull_thread.setDaemon(True)
        self.pull_thread.start()

        self.curr_bv = None
        self.curr_func = None

    #
    #   Multithreaded Stuff
    #

    def pull_routine(self):
        while True:
            # pull the repo every 10 seconds
            if self.check_client() and self.client.has_remote \
                    and (
                    self.client._last_pull_attempt_at is None
                    or (datetime.datetime.now() - self.client._last_pull_attempt_at).seconds > 10
            ):
                # Pull new items
                self.client.pull()

            if self.check_client():
                # reload info panel every 10 seconds
                if self.info_panel is not None and time.time() - self._last_reload > 10:
                    try:
                        self._last_reload = time.time()
                        self.info_panel.reload()
                    except RuntimeError:
                        # the panel has been closed
                        self.info_panel = None

            # Snooze
            time.sleep(1)

    #
    #   State Interaction Functions
    #

    def connect(self, user, path, init_repo=False, remote_url=None):
        binary_md5 = "" #TODO: how to get the md5 in Binja
        self.client = Client(user, path, binary_md5,
                             init_repo=init_repo,
                             remote_url=remote_url,
                             )
        BinsyncController._parse_and_display_connection_warnings(self.client.connection_warnings)
        print(f"[BinSync]: Client has connected to sync repo with user: {user}.")

    def check_client(self, message_box=False):
        if self.client is None:
            if message_box:
                QMessageBox.critical(
                    None,
                    "BinSync: Error",
                    "BinSync client does not exist.\n"
                    "You haven't connected to a binsync repo. Please connect to a binsync repo first.",
                    QMessageBox.Ok,
                )
            return False
        return True

    def state_ctx(self, user=None, version=None, locked=False):
        return self.client.state_ctx(user=user, version=version, locked=locked)

    def status(self):
        if self.check_client():
            if self.client.has_remote:
                return SyncControlStatus.CONNECTED
            return SyncControlStatus.CONNECTED_NO_REMOTE
        return SyncControlStatus.DISCONNECTED

    def status_string(self):
        stat = self.status()
        if stat == SyncControlStatus.CONNECTED:
            return f"Connected to a sync repo: {self.client.master_user}"
        elif stat == SyncControlStatus.CONNECTED_NO_REMOTE:
            return f"Connected to a sync repo (no remote): {self.client.master_user}"
        else:
            return "Not connected to a sync repo"

    @init_checker
    def users(self):
        return self.client.users()

    #
    #   DataBase Fillers
    #

    # TODO: support structs in Binja
    #@init_checker
    #@make_ro_state
    #def fill_structs(self, user=None, state=None):
    #    """
    #    Grab all the structs from a specified user, then fill them locally
    #
    #    @param user:
    #    @param state:
    #    @return:
    #    """
    #    # sanity check, the desired user has some structs to sync
    #    pulled_structs: List[Struct] = self.pull_structs(user=user, state=state)
    #    if len(pulled_structs) <= 0:
    #        print(f"[BinSync]: User {user} has no structs to sync!")
    #        return 0
    #
    #    # convert each binsync struct into an ida struct and set it in the GUI
    #    for struct in pulled_structs:
    #        compat.set_ida_struct(struct, self)
    #
    #    # set the type of each member in the structs
    #    all_typed_success = True
    #    for struct in pulled_structs:
    #        all_typed_success &= compat.set_ida_struct_member_types(struct, self)
    #
    #    return all_typed_success


    #
    #   Pullers
    #

    @init_checker
    def sync_all(self, user=None, state=None):
        # copy the actual state from the other user
        self.client.sync_states(user=user)
        new_state = self.client.get_state(user=self.client.master_user)
        func_addrs = new_state.functions.keys()
        print("[BinSync]: Target Addrs for sync:", [hex(x) for x in func_addrs])

        # set the new stuff in the UI
        for func_addr in func_addrs:
            self.fill_function(func_addr, user=self.client.master_user)

    def set_curr_bv(self, bv):
        self.curr_bv = bv

    def mark_as_current_function(self, bv, bn_func):
        self.curr_bv = bv
        self.curr_func = bn_func
        self.control_panel.reload()

    def current_function(self, message_box=False):
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            if message_box:
                show_message_box(
                    "UI contexts not found",
                    "No UI context is available. Please open a binary first.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon,
                )
            return None
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
            return None
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


    @init_checker
    @make_ro_state
    def fill_function(self, bn_func: binaryninja.function.Function, user=None, state=None) -> None:
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
        existing_stack_vars: Dict[int, Any] = dict((v.storage, v) for v in bn_func.stack_layout
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

    #
    #   Pushers
    #

    @init_checker
    @make_state
    def push_function(self, bn_func: binaryninja.function.Function, user=None, state=None):
        # Push function
        func = binsync.data.Function(
            int(bn_func.start)
        )  # force conversion from long to int
        func.name = bn_func.name
        state.set_function(func)

    @init_checker
    @make_state
    def push_patch(self, patch, user=None, state=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state
    def push_stack_variable(self, bn_func: binaryninja.Function, stack_var: binaryninja.function.Variable,
                            user=None, state=None):
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
        state.set_stack_variable(v, stack_var.storage, bn_func.start)

    @init_checker
    @make_state
    def push_stack_variables(self, bn_func, user=None, state=None):
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
            self.push_stack_variable(bn_func, stack_var, state=state, user=user)

    @init_checker
    @make_state
    def remove_all_comments(self, bn_func: binaryninja.function.Function, user=None, state=None) -> None:
        for _, ins_addr in bn_func.instructions:
            if ins_addr in state.comments:
                state.remove_comment(ins_addr)

    @init_checker
    @make_state
    def push_comments(self, comments: Dict[int,str], user=None, state=None) -> None:
        # Push comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            state.set_comment(comm_addr, comment)

    #
    #   Pullers
    #

    @init_checker
    @make_ro_state
    def pull_stack_variables(self, bn_func, user=None, state=None) -> Dict[int,StackVariable]:
        try:
            return {k: v for k, v in state.get_stack_variables(bn_func.start)}
        except KeyError:
            return { }

    @init_checker
    @make_ro_state
    def pull_stack_variable(self, bn_func, offset: int, user=None, state=None) -> StackVariable:
        return state.get_stack_variable(bn_func.start, offset)

    @init_checker
    @make_ro_state
    def pull_function(self, bn_func, user=None, state=None) -> Optional[Function]:
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
    def pull_comment(self, func_addr, addr, user=None, state=None) -> Optional[str]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        try:
            return state.get_comment(func_addr, addr)
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_comments(self, func_addr, user=None, state=None) -> Optional[Iterable[str]]:
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        return state.get_comments(func_addr)

    @staticmethod
    def _parse_and_display_connection_warnings(warnings):
        warning_text = ""

        for warning in warnings:
            if warning == ConnectionWarnings.HASH_MISMATCH:
                warning_text += "Warning: the hash stored for this BinSync project does not match"
                warning_text += " the hash of the binary you are attempting to analyze. It's possible"
                warning_text += " you are working on a different binary.\n"

        if len(warning_text) > 0:
            QMessageBox.warning(
                None,
                "BinSync: Connection Warnings",
                warning_text,
                QMessageBox.Ok,
            )

    @staticmethod
    def friendly_datetime(time_before):
        # convert
        if isinstance(time_before, int):
            dt = datetime.datetime.fromtimestamp(time_before)
        elif isinstance(time_before, datetime.datetime):
            dt = time_before
        else:
            return ""

        now = datetime.datetime.now()
        if dt <= now:
            diff = now - dt
            ago = True
        else:
            diff = dt - now
            ago = False
        diff_days = diff.days
        diff_sec = diff.seconds

        if diff_days >= 1:
            s = "%d days" % diff_days
        elif diff_sec >= 60 * 60:
            s = "%d hours" % int(diff_sec / 60 / 60)
        elif diff_sec >= 60:
            s = "%d minutes" % int(diff_sec / 60)
        else:
            s = "%d seconds" % diff_sec

        s += " ago" if ago else " in the future"
        return s