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

import re
from typing import Dict, List, Tuple, Optional, Iterable, Any
import hashlib
import logging
from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType


from binsync.common.controller import *
from binsync.data import StackOffsetType, FunctionHeader
import binsync

l = logging.getLogger(__name__)

#
# Controller
#

class BinjaBinSyncController(BinSyncController):
    def __init__(self):
        super(BinjaBinSyncController, self).__init__()
        self.bv = None

    def binary_hash(self) -> str:
        return hashlib.md5(self.bv.file.raw[:]).hexdigest()

    def active_context(self):
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

        return binsync.data.Function(
            func.start, 0, header=FunctionHeader(func.name, func.start)
        )

    def binary_path(self) -> Optional[str]:
        try:
            return self.bv.file.filename
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        func = self.bv.get_function_at(func_addr)
        if not func:
            return 0

        return func.highest_address - func.start

    @init_checker
    @make_ro_state
    def fill_function(self, func_addr, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """
        bn_func = self.bv.get_function_at(func_addr)
        sync_func = self.pull_function(func_addr, user=user, state=state)
        if sync_func is None:
            return

        # name
        if sync_func.name and sync_func.name != bn_func.name:
            bn_func.name = sync_func.name

        # comments
        for addr, comment in self.pull_func_comments(bn_func.start, user=user, state=state).items():
            bn_func.set_comment_at(addr, comment.comment)

        # stack variables
        existing_stack_vars: Dict[int, Any] = dict((v.storage, v) for v in bn_func.stack_layout
                                                  if v.source_type == VariableSourceType.StackVariableSourceType)
        for offset, stack_var in self.pull_stack_variables(bn_func.start, user=user, state=state).items():
            bn_offset = stack_var.get_offset(StackOffsetType.BINJA)
            # skip if this variable already exists
            type_, _ = bn_func.view.parse_type_string(stack_var.type)
            if bn_offset in existing_stack_vars \
                    and existing_stack_vars[bn_offset].name == stack_var.name \
                    and existing_stack_vars[bn_offset].type == type_:
                continue

            existing_stack_vars[bn_offset].name = stack_var.name
            last_type = existing_stack_vars[bn_offset].type

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
    @make_state_with_func
    def push_function_header(self, bs_func_header: binsync.data.FunctionHeader, user=None, state=None):
        # Push function
        #func = binsync.data.FunctionHeader(name, addr)  # force conversion from long to int
        state.set_function_header(bs_func_header)

    @init_checker
    @make_state
    def push_patch(self, patch, user=None, state=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state_with_func
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
    @make_state_with_func
    def push_comments(self, comments: Dict[int,str], func_addr=None, user=None, state=None) -> None:
        # Push comments
        for addr, comment in comments.items():
            cmt = binsync.data.Comment(addr, comment, decompiled=True)
            state.set_comment(cmt)
