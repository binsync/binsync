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

from binaryninja import SymbolType
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

from binsync.common.controller import BinSyncController, fill_event, init_checker
from binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, FunctionArgument, StackVariable, StackOffsetType,
    Comment, GlobalVariable, Patch,
    Enum, Struct
)
import binsync

from .artifact_lifter import BinjaArtifactLifter

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
        super(BinjaBinSyncController, self).__init__(artifact_lifter=BinjaArtifactLifter(self))
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
    @background_and_wait
    def fill_struct(self, struct_name, user=None, state=None, header=True, members=True):
        pass

    @init_checker
    @background_and_wait
    def fill_global_var(self, var_addr, user=None, state=None):
        pass

    @init_checker
    @background_and_wait
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """
        sync_func: Function = artifact
        bn_func = self.bv.get_function_at(self.artifact_lifer.lower_addr(sync_func.addr))
        self.sync_lock = True
        # sync_func = self.merge_function_into_master(sync_func) ????

        changes = super(BinjaBinSyncController, self).fill_function(
            func_addr, user=user, artifact=artifact, bn_func=bn_func, **kwargs
        )
        bn_func.reanalyze()
        self.sync_lock = False
        return changes

        """
        updates = False
        bn_func = self.bv.get_function_at(self.artifact_lifer.lower_addr(func_addr))
        sync_func = state.get_function(func_addr)
        if sync_func is None or bn_func is None:
            return

        self.sync_lock = True
        sync_func = self.merge_function_into_master(sync_func)
        
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

        sync_cmts = self.pull_artifact(Comment, func_addr, many=True, state=state, user=user)
        for addr, comment in sync_cmts.items():
            if not comment:
                continue

            bn_func.set_comment_at(addr, comment.comment)
            updates |= True

        bn_func.reanalyze()
        if updates:
            l.info(f"New data synced for \'{user}\' on function {hex(bn_func.start)}.")
        else:
            l.info(f"No new data was set either by failure or lack of differences.")

        self.sync_lock = False
        return updates
        """

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, bn_func=None, **kwargs):
        updates = False
        sync_header: FunctionHeader = artifact

        if sync_header:
            # func name
            if sync_header.name and sync_header.name != bn_func.name:
                bn_func.name = sync_header.name
                updates |= True

            # ret type
            if sync_header.ret_type and \
                    sync_header.ret_type != bn_func.return_type.get_string_before_name():

                valid_type = False
                try:
                    new_type, _ = self.bv.parse_type_string(sync_header.ret_type)
                    valid_type = True
                except Exception:
                    pass

                if valid_type:
                    bn_func.return_type = new_type
                    updates |= True

            # parameters
            if sync_header.args:
                prototype_tokens = [sync_header.ret_type] if sync_header.ret_type \
                    else [bn_func.return_type.get_string_before_name()]

                prototype_tokens.append("(")
                for idx, func_arg in sync_header.args.items():
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

        return updates

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, bn_func=None, **kwargs):
        updates = False
        bs_stack_var: StackVariable = artifact

        existing_stack_vars: Dict[int, Any] = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType
        }

        bn_offset = bs_stack_var.get_offset(StackOffsetType.BINJA)

        if bn_offset in existing_stack_vars:
            if existing_stack_vars[bn_offset].name != bs_stack_var.name:
                existing_stack_vars[bn_offset].name = bs_stack_var.name

            valid_type = False
            try:
                type_, _ = self.bv.parse_type_string(bs_stack_var.type)
                valid_type = True
            except Exception:
                pass

            if valid_type:
                if existing_stack_vars[bn_offset].type != type_:
                    existing_stack_vars[bn_offset].type = type_
                try:
                    bn_func.create_user_stack_var(bn_offset, type_, bs_stack_var.name)
                    bn_func.create_auto_stack_var(bn_offset, type_, bs_stack_var.name)
                except Exception as e:
                    l.warning(f"BinSync could not sync stack variable at offset {bn_offset}: {e}")

                updates |= True

        return updates

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, bn_func=None, **kwargs):
        updates = False
        comment: Comment = artifact

        if asdfasdfasdadfadfadfadfaf:
            bn_func.set_comment_at(comment.addr, comment.comment)
            updates |= True

        return updates

    #
    # Artifact API
    #

    def functions(self) -> Dict[int, Function]:
        funcs = {}
        for bn_func in self.bv.functions:
            if bn_func.symbol.type != SymbolType.FunctionSymbol:
                continue

            funcs[bn_func.start] = Function(bn_func.start, bn_func.total_bytes)
            funcs[bn_func.start].name = bn_func.name

        return funcs

    def function(self, addr) -> Optional[Function]:
        """
        TODO: fix how types and offsets are set

        @param addr:
        @return:
        """
        bn_func = self.bv.get_function_at(addr)
        if not bn_func:
            return None

        func = Function(bn_func.start, bn_func.total_bytes)
        func_header = FunctionHeader(
            bn_func.name,
            func.addr,
            ret_type=bn_func.return_type.get_string_before_name(),
            args={
                idx: FunctionArgument(idx, param.name, str(param.type), param.type.width)
                for idx, param in enumerate(bn_func.function_type.parameters)
            }
        )
        stack_vars = {
            v.storage: StackVariable(v.storage, StackOffsetType.BINJA, v.name, str(v.type), v.type.width, func.addr)
            for v in bn_func.stack_layout if v.source_type == VariableSourceType.StackVariableSourceType
        }
        func.header = func_header
        func.stack_vars = stack_vars

        return func

    def global_vars(self) -> Dict[int, GlobalVariable]:
        return {
            addr: GlobalVariable(addr, self.bv.get_symbol_at(addr) or f"data_{addr:x}")
            for addr, var in self.bv.data_vars.items()
        }
    
    def global_var(self, addr) -> Optional[GlobalVariable]:
        try:
            var = self.bv.data_vars[addr]
        except KeyError:
            return None 
            
        gvar = GlobalVariable(
            addr, self.bv.get_symbol_at(addr) or f"data_{addr:x}", type_str=str(var.type), size=var.type.width
        )
        return gvar