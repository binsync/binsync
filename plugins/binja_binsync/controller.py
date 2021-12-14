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


from binsync.common.controller import *
from binsync.data import StackOffsetType
import binsync

#
# Controller
#

class BinjaBinSyncController(BinSyncController):
    def __init__(self):
        super(BinjaBinSyncController, self).__init__()
        self.curr_bv = None
        self.curr_func = None

    def binary_hash(self) -> str:
        return ""

    def active_context(self):
        return None

    def set_curr_bv(self, bv):
        self.curr_bv = bv

    def mark_as_current_function(self, bv, bn_func):
        self.curr_bv = bv
        self.curr_func = bn_func

    def current_function(self):
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            return None

        ctx = all_contexts[0]
        handler = ctx.contentActionHandler()
        if handler is None:
            return None

        actionContext = handler.actionContext()
        func = actionContext.function
        if func is None:
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
            _comment = self.pull_comment(bn_func.start, ins_addr, user=user, state=state)
            if _comment is not None:
                bn_func.set_comment_at(ins_addr, _comment.comment)

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

            existing_stack_vars[bn_offset].name = stack_var.name
            last_type = existing_stack_vars[bn_offset].type
            #print(f"LAST TYPE: {last_type}")

            try:
                bn_func.create_user_stack_var(bn_offset, last_type, stack_var.name)
                bn_func.create_auto_stack_var(bn_offset, last_type, stack_var.name)
            except Exception as e:
                print(f"[BinSync]: Could not sync stack variable {bn_offset}: {e}")

        bn_func.reanalyze()
        print(f"[Binsync]: New data synced for \'{user}\' on function {hex(bn_func.start)}.")

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
    def push_comments(self, func, comments: Dict[int,str], user=None, state=None) -> None:
        # Push comments
        for addr, comment in comments.items():
            cmt = binsync.data.Comment(func.start, int(addr), comment, decompiled=True)
            state.set_comment(cmt)

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