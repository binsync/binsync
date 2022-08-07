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
from typing import Dict, List, Tuple, Optional
from collections import OrderedDict, defaultdict

import idc
import idaapi
import idautils
import ida_struct
import ida_hexrays
import ida_funcs
import ida_kernwin

import binsync
from binsync.common.controller import BinSyncController, init_checker, fill_event
from binsync import (
    StackVariable, StackOffsetType, Function, FunctionHeader, Struct, Comment, GlobalVariable, Enum, State, Patch
)
from . import compat
from .artifact_lifter import IDAArtifactLifter

_l = logging.getLogger(name=__name__)


def update_on_view(f):
    wraps(f)
    def _update_on_view(self: IDABinSyncController, func_addr, *args, **kwargs):
        # always execute something we are looking at
        active_ctx = self.active_context()
        if active_ctx and active_ctx.addr == func_addr:
            return f(self, func_addr, *args, **kwargs)

        # otherwise, execute next time we look at it through the hooks
        task = UpdateTask(f, self, func_addr, *args, **kwargs)
        self.update_states[func_addr].add_update_task(task)

    return _update_on_view


#
#   Wrapper Classes
#


class UpdateTask:
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __eq__(self, other):
        return (
            isinstance(other, UpdateTask)
            and other.func == other.func
            and other.kwargs == other.kwargs
        )

    def __hash__(self):
        expanded_kwargs = list()
        for k, v in self.kwargs.items():
            expanded_kwargs.append(f"{k}={v}")
        return hash((self.func, *self.args, *expanded_kwargs))

    def dump(self):
        return self.func, self.args, self.kwargs


class UpdateTaskState:
    def __init__(self):
        self.update_tasks: Dict[UpdateTask, bool] = OrderedDict()
        self.update_tasks_lock = threading.Lock()

    def toggle_auto_sync_task(self, update_task):
        with self.update_tasks_lock:
            # delete the task if it is an auto_sync task already
            if update_task in list(self.update_tasks.keys()) and self.update_tasks[update_task]:
                del self.update_tasks[update_task]
                return False

            # set/make the task if its not auto_sync already
            self.update_tasks[update_task] = True
            return True

    def add_update_task(self, update_task):
        with self.update_tasks_lock:
            self.update_tasks[update_task] = False

    def do_updates(self):
        with self.update_tasks_lock:
            # run each task in the update task queue
            for update_task in list(self.update_tasks.keys()):
                f, args, kwargs = update_task.dump()
                auto_sync = self.update_tasks[update_task]

                # doing task
                try:
                    f(*args, **kwargs)
                except Exception:
                    print(f"[BinSync]: failed to execute cache of {f} with {args}")

                # remove the task if its not an auto_sync task
                if not auto_sync:
                    del self.update_tasks[update_task]


#
#   Controller
#

class IDABinSyncController(BinSyncController):
    def __init__(self):
        super(IDABinSyncController, self).__init__(artifact_lifter=IDAArtifactLifter(self))

        # view change callback
        self._updated_ctx = None

        # update state for only updating when needed
        # api locks
        self.api_lock = threading.Lock()
        self.api_count = 0
        self.update_states = defaultdict(UpdateTaskState)

    #
    #   Multithreaded locks and setters
    #

    def make_controller_cmd(self, cmd_func, *args, **kwargs):
        with self.queue_lock:
            if isinstance(args[0], Struct):
                self.cmd_queue[args[0].name] = (cmd_func, args, kwargs)
            else:
                self.cmd_queue[time.time()] = (cmd_func, args, kwargs)

    #
    # Controller Interaction
    #

    def binary_hash(self) -> str:
        return idc.retrieve_input_file_md5().hex()

    def active_context(self):
        return self._updated_ctx

    def update_active_context(self, addr):
        if not addr or addr == idaapi.BADADDR:
            return

        func_addr = compat.ida_func_addr(addr)
        if func_addr is None:
            return

        func = binsync.data.Function(
            func_addr, 0, header=FunctionHeader(compat.get_func_name(func_addr), func_addr)
        )
        self._updated_ctx = func

    def binary_path(self) -> Optional[str]:
        return compat.get_binary_path()

    def get_func_size(self, func_addr) -> int:
        return compat.get_func_size(func_addr)

    def goto_address(self, func_addr) -> None:
        compat.jumpto(func_addr)

    #
    # IDA DataBase Fillers
    #

    @init_checker
    @fill_event
    def fill_struct(self, struct_name, user=None, header=True, members=True, artifact=None, **kwargs):
        data_changed = False
        struct: Struct = artifact

        if not struct:
            _l.warning("Was not able to find the struct you requested in other users name")
            return None

        if header:
            data_changed |= compat.set_ida_struct(struct, self)

        if members:
            data_changed |= compat.set_ida_struct_member_types(struct, self)

        return data_changed

    @init_checker
    @fill_event
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        changed = False
        global_var: GlobalVariable = artifact
        if global_var and global_var.name:
            changed = compat.set_global_var_name(var_addr, global_var.name)

        if changed:
            ctx = self.active_context()
            if ctx:
                compat.refresh_pseudocode_view(ctx.addr)

        return changed

    @init_checker
    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        func: Function = artifact
        ida_code_view = compat.acquire_pseudocode_vdui(func.addr)
        changes = super(IDABinSyncController, self).fill_function(
            func_addr, user=user, artifact=artifact, ida_code_view=ida_code_view, **kwargs
        )
        compat.refresh_pseudocode_view(func.addr)
        return changes

    @init_checker
    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        cmt: Comment = artifact
        res = compat.set_ida_comment(addr, cmt.comment, decompiled=cmt.decompiled)
        if not res:
            _l.warning(f"Failed to sync comment at <{hex(addr)}>: \'{cmt.comment}\'")

        return res

    @init_checker
    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, ida_code_view=None, **kwargs):
        stack_var: StackVariable = artifact
        frame = idaapi.get_frame(stack_var.addr)
        changes = False
        if frame is None or frame.memqty <= 0:
            _l.warning(f"Function {stack_var.addr:x} does not have an associated function frame. Stopping sync here!")
            return False

        if ida_struct.set_member_name(frame, offset, stack_var.name):
            changes |= True

        ida_type = compat.convert_type_str_to_ida_type(stack_var.type)
        if ida_type is None:
            _l.warning(f"IDA Failed to parse type for stack var {stack_var}")
            return changes

        changes |= compat.set_stack_vars_types({offset: ida_type}, ida_code_view, self)
        return changes

    @init_checker
    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, ida_code_view=None, **kwargs):
        func_header: FunctionHeader = artifact
        updated_header = compat.set_function_header(ida_code_view, func_header)
        return updated_header

    #
    # Artifact API
    #

    def functions(self) -> Dict[int, Function]:
        return compat.functions()

    def function(self, addr) -> Optional[Function]:
        return compat.function(addr)

    def global_vars(self) -> Dict[int, GlobalVariable]:
        return compat.global_vars()

    def global_var(self, addr) -> Optional[GlobalVariable]:
        return compat.global_var(addr)

    def structs(self) -> Dict[str, Struct]:
        return compat.structs()

    def struct(self, name) -> Optional[Struct]:
        return compat.struct(name)

    def enums(self) -> Dict[str, Enum]:
        return compat.enums()

    def enum(self, name) -> Optional[Enum]:
        return compat.enum(name)
    #
    # Utils
    #

    @init_checker
    def _typestr_in_state_structs(self, type_str, user=None, state=None):
        binsync_structs = state.get_structs()
        for struct in binsync_structs:
            if struct.name in type_str:
                return True

        return False
