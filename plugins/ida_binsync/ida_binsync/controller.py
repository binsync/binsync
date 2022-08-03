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
from binsync.common.controller import BinSyncController, init_checker, make_ro_state
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

    return _update_on_view()


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
        super(IDABinSyncController, self).__init__(IDAArtifactLifter(self))

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

    def inc_api_count(self):
        with self.api_lock:
            self.api_count += 1

    def dec_api_count(self):
        with self.api_lock:
            self.api_count -= 1

    def reset_api_count(self):
        with self.api_lock:
            self.api_count = 0

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
    @make_ro_state
    def fill_struct(self, struct_name, user=None, state=None, header_only=False):
        data_changed = False
        struct: Struct = self.pull_artifact(Struct, struct_name, state=state)

        if not struct:
            _l.warning("Was not able to find the struct you requested in other users name")
            return None

        data_changed |= compat.set_ida_struct(struct, self) \
            if header_only else compat.set_ida_struct_member_types(struct, self)

        _l.info(
            f"New data synced from \'{user}\' on struct \'{struct_name}\' {'header' if header_only else 'members'}."
            if data_changed else \
            f"No new data was set either by failure or lack of differences."
        )
        return data_changed

    @init_checker
    @make_ro_state
    def fill_structs(self, user=None, state=None):
        """
        Grab all the structs from a specified user, then fill them locally

        @param user:
        @param state:
        @param artifacts:
        @return:
        """
        data_changed = False
        structs = self.pull_artifact(Struct, many=True, state=state)
        for struct_name, struct in structs.items():
            data_changed |= self.fill_struct(struct_name, user=user, state=state, header=True)

        for struct_name, struct in structs.items():
            data_changed |= self.fill_struct(struct_name, user=user, state=state, header=False)

        return data_changed

    @init_checker
    @make_ro_state
    def fill_global_var(self, var_addr, user=None, state=None):
        changed = False
        global_var: GlobalVariable = self.pull_artifact(GlobalVariable, var_addr, state=state)
        if global_var and global_var.name:
            self.inc_api_count()
            changed = compat.set_global_var_name(var_addr, global_var.name)
            if not changed:
                self.dec_api_count()

        if changed:
            _l.info(f"Synced variable at {hex(var_addr)} from user {user}.")
            ctx = self.active_context()
            if ctx:
                compat.refresh_pseudocode_view(ctx.addr)
        else:
            _l.info(f"No change synced for {hex(var_addr)} from user {user}")

        return changed

    @init_checker
    @make_ro_state
    def fill_function(self, func_addr, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @func_adrr.
        """
        data_changed = False

        # sanity check this function
        ida_func = ida_funcs.get_func(self.artifact_lifer.lower_addr(func_addr))
        if ida_func is None:
            _l.warning(f"IDA function does not exist on sync for \'{user}\' on function {hex(func_addr)}.")
            return data_changed

        #
        # FUNCTION HEADER
        #

        # function should exist in pulled state
        binsync_func: Function = state.get_function(func_addr)
        if binsync_func is None:
            return data_changed

        # make function prepared for either merging or not
        binsync_func = self.generate_func_for_sync_level(binsync_func)

        ida_code_view = compat.acquire_pseudocode_vdui(ida_func.start_ea)
        # check if a header has been set for the func
        if binsync_func.header:
            updated_header = False
            try:
                # allow set_func_header to return None to let us know a type is missing
                updated_header = compat.set_function_header(ida_code_view, binsync_func.header, self, exit_on_bad_type=True)
            except Exception as e:
                _l.warning(f"Header filling failed with exception {e}")
                self.reset_api_count()

            # this means the type failed
            if updated_header is None:
                # we likely are missing a custom type. Try again!
                data_changed |= self.fill_structs(user=user, state=state)
                try:
                    updated_header = compat.set_function_header(ida_code_view, binsync_func.header, self)
                except Exception as e:
                    _l.warning(f"Header filling failed with exception {e}, even after pulling custom types.")
                    self.reset_api_count()

            data_changed |= updated_header

        #
        # COMMENTS
        #

        sync_cmts = self.pull_artifact(Comment, func_addr, many=True, state=state, user=user)
        for addr, cmt in sync_cmts.items():
            self.inc_api_count()
            res = compat.set_ida_comment(addr, cmt.comment, decompiled=cmt.decompiled)
            if not res:
                _l.warning(f"Failed to sync comment at <{hex(addr)}>: \'{cmt.comment}\'")
                self.reset_api_count()

        #
        # STACK VARIABLES
        #

        frame = idaapi.get_frame(ida_func.start_ea)
        if frame is None or frame.memqty <= 0:
            _l.warning("Function %#x does not have an associated function frame. Stopping sync here!",
                     ida_func.start_ea)
            return data_changed

        # collect and covert the info of each stack variable
        existing_stack_vars = {}
        for offset, var in compat.get_func_stack_var_info(ida_func.start_ea).items():
            existing_stack_vars[compat.ida_to_angr_stack_offset(ida_func.start_ea, offset)] = var

        stack_vars_to_set = {}
        # only try to set stack vars that actually exist
        for offset, stack_var in binsync_func.stack_vars.items():
            if offset in existing_stack_vars:
                # change the variable's name
                if stack_var.name != existing_stack_vars[offset].name:
                    self.inc_api_count()
                    if ida_struct.set_member_name(frame, existing_stack_vars[offset].stack_offset, stack_var.name):
                        data_changed |= True

                # check if the variables type should be changed
                if ida_code_view and stack_var.type != existing_stack_vars[offset].type:
                    # validate the type is convertible
                    ida_type = compat.convert_type_str_to_ida_type(stack_var.type)
                    if ida_type is None:
                        # its possible the type is just a custom type from the same user
                        # TODO: make it possible to sync a single struct
                        if self._typestr_in_state_structs(stack_var.type, user=user, state=state):
                            _l.info(f"Importing structs from user {user}")
                            data_changed |= self.fill_structs(user=user, state=state)

                        ida_type = compat.convert_type_str_to_ida_type(stack_var.type)
                        # it really is just a bad type
                        if ida_type is None:
                            _l.debug(f"Failed to parse stack variable stored type at offset"
                                     f" {hex(existing_stack_vars[offset].stack_offset)} with type {stack_var.type}"
                                     f" on function {hex(ida_func.start_ea)}.")
                            continue

                    # queue up the change!
                    stack_vars_to_set[existing_stack_vars[offset].stack_offset] = ida_type

            # change the type of all vars that need to be changed
            # NOTE: api_count is incremented inside the function
            data_changed |= compat.set_stack_vars_types(stack_vars_to_set, ida_code_view, self)

        compat.refresh_pseudocode_view(self.artifact_lifer.lower_addr(binsync_func.addr))
        if data_changed:
            _l.info(f"New data synced for \'{user}\' on function {hex(ida_func.start_ea)}.")
        else:
            _l.info(f"No new data was set either by failure or lack of differences.")

        return data_changed

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
