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
import threading
import functools
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
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.mainthread import execute_on_main_thread, is_main_thread


from binsync.common.controller import *
from binsync.data import StackOffsetType, FunctionHeader
import binsync

l = logging.getLogger(__name__)

#
# Helpers
#


def background_and_wait(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        output = [None]

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        thread = threading.Thread(target=thunk)
        thread.start()
        thread.join()

        return output[0]
    return wrapper


#
# Controller
#

class BinjaBinSyncController(BinSyncController):
    def __init__(self):
        super(BinjaBinSyncController, self).__init__()
        self.bv = None
        self.sync_lock = False

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

    def goto_address(self, func_addr) -> None:
        self.bv.offset = func_addr

    #
    # Fillers
    #

    @init_checker
    @make_ro_state
    @background_and_wait
    def fill_function(self, func_addr, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """
        updates = False
        bn_func = self.bv.get_function_at(func_addr)
        sync_func = self.pull_function(func_addr, user=user, state=state) # type: Function
        if sync_func is None or bn_func is None:
            return

        self.sync_lock = True
        sync_func = self.generate_func_for_sync_level(sync_func)

        #
        # header
        #

        if sync_func.header:
            # func name
            if sync_func.name and sync_func.name != bn_func.name:
                bn_func.name = sync_func.name
                updates |= True

            # ret type
            if sync_func.header.ret_type and \
                    sync_func.header.ret_type != bn_func.return_type.get_string_before_name():

                valid_type = False
                try:
                    new_type, _ = self.bv.parse_type_string(sync_func.header.ret_type)
                    valid_type = True
                except Exception:
                    pass

                if valid_type:
                    bn_func.return_type = new_type
                    updates |= True

            # parameters
            if sync_func.header.args:
                prototype_tokens = [sync_func.header.ret_type] if sync_func.header.ret_type \
                    else [bn_func.return_type.get_string_before_name()]

                prototype_tokens.append("(")
                for idx, func_arg in sync_func.header.args.items():
                    prototype_tokens.append(func_arg.type_str)
                    prototype_tokens.append(func_arg.name)
                    prototype_tokens.append(",")

                if prototype_tokens[-1] == ",":
                    prototype_tokens[-1] = ")"

                prototype_str = " ".join(prototype_tokens)

                valid_type = False
                try:
                    bn_prototype, _ = self.bv.parse_type_string(prototype_str)
                    valid_type = True
                except Exception:
                    pass

                if valid_type:
                    bn_func.function_type = bn_prototype
                    updates |= True

        #
        # stack variables
        #

        existing_stack_vars: Dict[int, Any] = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType
        }

        for offset, stack_var in sync_func.stack_vars.items():
            bn_offset = stack_var.get_offset(StackOffsetType.BINJA)
            # skip if this variable already exists
            if bn_offset not in existing_stack_vars:
                continue

            if existing_stack_vars[bn_offset].name != stack_var.name:
                existing_stack_vars[bn_offset].name = stack_var.name

            valid_type = False
            try:
                type_, _ = self.bv.parse_type_string(stack_var.type)
                valid_type = True
            except Exception:
                pass

            if valid_type:
                if existing_stack_vars[bn_offset].type != type_:
                    existing_stack_vars[bn_offset].type = type_

                try:
                    bn_func.create_user_stack_var(bn_offset, type_, stack_var.name)
                    bn_func.create_auto_stack_var(bn_offset, type_, stack_var.name)
                except Exception as e:
                    l.warning(f"BinSync could not sync stack variable at offset {bn_offset}: {e}")

                updates |= True

        #
        # comments
        #

        for addr, comment in self.pull_func_comments(bn_func.start, user=user).items():
            bn_func.set_comment_at(addr, comment.comment)
            updates |= True

        bn_func.reanalyze()
        if updates:
            l.info(f"New data synced for \'{user}\' on function {hex(bn_func.start)}.")
        else:
            l.info(f"No new data was set either by failure or lack of differences.")

        self.sync_lock = False
        return updates

    #
    #   Pushers
    #

    @init_checker
    @make_state_with_func
    def push_function_header(self, addr, bs_func_header: binsync.data.FunctionHeader, user=None, state=None, api_set=False):
        # Push function header
        state.set_function_header(bs_func_header, set_last_change=not api_set)

    @init_checker
    @make_state
    def push_patch(self, patch, user=None, state=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state_with_func
    def push_stack_variable(self, addr, stack_offset, name, type_str, size, user=None, state=None, api_set=False):
        v = StackVariable(
            stack_offset,
            StackOffsetType.IDA,
            name,
            type_str,
            size,
            addr
        )
        state.set_stack_variable(v, stack_offset, addr)

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
