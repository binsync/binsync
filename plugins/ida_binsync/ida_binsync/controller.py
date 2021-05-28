# ----------------------------------------------------------------------------
# This file contains the BinsyncController class which acts as the the
# bridge between the plugin UI and direct calls to the binsync client found in
# the core of the binsync. In the controller, you will find code used to make
# pushes and pulls of user changes.
#
# You will also notice that the BinsyncController runs two extra threads in
# it:
#   1. Binsync "git pulling" thread to constantly get changes from others
#   2. Command Routine to get hooked changes to IDA attributes
#
# The second point is more complicated because it acts as the queue of
# runnable actions that are queued from inside the hooks.py file.
# Essentially, every change that happens in IDA from the main user triggers
# a hook which will push an action to be preformed onto the command queue;
# Causing a "git push" on every change.
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import
from functools import wraps
import re
import threading
import time
import datetime
import logging
from typing import Dict, List, Tuple
from collections import OrderedDict

from PyQt5.QtWidgets import QMessageBox

import ida_hexrays
import idc
import idaapi
import idautils
import ida_struct
import ida_idaapi

import binsync
from binsync import Client
from binsync.data import StackVariable, StackOffsetType, Function, Struct
from . import compat

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

def last_push(f):
    """
    Once a push function has been executed, perform an update on the last push time,
    last push function, and the local function name for the master user. 
    """
    @wraps(f)
    def set_last_push(self, *args, **kwargs):
        print(args)
        print(kwargs)
        # Get the attribute address
        attr_addr = args[0] # First arg should be attr_addr. If not, be scared.

        # Create our last push time, last push func, and func name
        last_push_time = int(time.time())
        last_push_func = compat.ida_func_addr(attr_addr)
        print(f"[LAST PUSH FUNC] {last_push_func}")
        func_name = compat.get_func_name(last_push_func)        

        # Call the function first. This way any changes
        # can be set. (func changed, time finally modified, etc.)
        f(self, *args, **kwargs)

        # Call the binsync proper client last_push
        self._client.last_push(last_push_func, last_push_time, func_name)
    return set_last_push
        

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
            state = self._client.get_state(user=user)
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
            state.save()
            return r
        else:
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
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
            state = self._client.get_state(user=user)
        kwargs['state'] = state
        kwargs['user'] = user
        return f(self, *args, **kwargs)
    return state_check


#
# Classes
#

class BinsyncClient(Client):
    def __init__(
        self,
        master_user,
        repo_root,
        binary_hash,
        function_callback,
        comment_callback,
        patch_callback,
        remote="origin",
        commit_interval=10,
        init_repo=False,
        remote_url=None,
        ssh_agent_pid=None,
        ssh_auth_sock=None
    ):

        binsync.Client.__init__(
            self,
            master_user,
            repo_root,
            binary_hash,
            remote=remote,
            commit_interval=commit_interval,
            init_repo=init_repo,
            remote_url=remote_url,
            ssh_agent_pid=ssh_agent_pid,
            ssh_auth_sock=ssh_auth_sock,
        )

        self.function_callback = function_callback
        self.comment_callback = comment_callback
        self.patch_callback = patch_callback

    # def save_state(self, state=None):
    #    print("ENTERING SAVE")
    #    binsync.Client.save_state(self, state=state)
    #    state = self.get_state()
    #    for addr in state.functions.keys():
    #        idaapi.set_name(addr, state.functions[addr].name)

    def update(self):
        """

        :return:
        """

        # do a pull... if there is a remote
        if self.has_remote:
            self.pull()

        print("IS DIRTY??", self.get_state().dirty)

        if self.has_remote:
            # do a push... if there is a remote
            self.push()

        self._last_commit_ts = time.time()


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

        self.control_panel = None

        # last push info
        self.last_push_time: int = None
        self.last_push_func: int = None

        # command locks
        self.queue_lock = threading.Lock()
        self.cmd_queue = OrderedDict()

        # api locks
        self.api_lock = threading.Lock()
        self.api_count = 0

        # start the pull routine
        self.pull_thread = threading.Thread(target=self.pull_routine)
        self.pull_thread.setDaemon(True)
        self.pull_thread.start()

    def make_controller_cmd(self, cmd_func, *args, **kwargs):
        self.queue_lock.acquire()
        if cmd_func == self.push_struct:
            self.cmd_queue[args[0].name] = (cmd_func, args, kwargs)
        else:
            self.cmd_queue[time.time()] = (cmd_func, args, kwargs)
        self.queue_lock.release()

    def eval_cmd_queue(self):
        self.queue_lock.acquire()
        if len(self.cmd_queue) > 0:
            # pop the first command from the queue
            cmd = self.cmd_queue.popitem(last=False)[1]
            self.queue_lock.release()

            # parse the command
            func = cmd[0]
            f_args = cmd[1]
            f_kargs = cmd[2]

            # call it!
            func(*f_args, **f_kargs)
            return 0
        self.queue_lock.release()

    """
    TODO:
    there is a bug here since we do a state read in another thread at possibly the same time.
    """
    def pull_routine(self):
        while True:
            # pull the repo every 10 seconds
            if self.check_client() and self._client.has_remote \
                    and (
                         self._client._last_pull_attempt_at is None
                         or (datetime.datetime.now() - self._client._last_pull_attempt_at).seconds > 10
                         ):
                # Pull new items
                self._client.pull()

                # reload the control panel if it's registered
                if self.control_panel is not None:
                    try:
                        self.control_panel.reload()
                    except RuntimeError:
                        # the panel has been closed
                        self.control_panel = None

            # run an operation every second
            if self.check_client() and self._client.has_remote:
                self.eval_cmd_queue()

            # Snooze
            time.sleep(1)

    def connect(self, user, path, init_repo, ssh_agent_pid=None, ssh_auth_sock=None):
        self._client = BinsyncClient(user, path, None, None, None, None, init_repo=init_repo,
                                     ssh_agent_pid=ssh_agent_pid, ssh_auth_sock=ssh_auth_sock)
        print(f"[Binsync]: Client has connected to sync repo with user: {user}.")

    def check_client(self, message_box=False):
        if self._client is None:
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

    def current_function(self):
        """
        :return:
        :rtype: Optional[ida_funcs.func_t]
        """
        ea = compat.get_screen_ea()
        if ea is None:
            return None
        func = idaapi.get_func(ea)
        return func

    def state_ctx(self, user=None, version=None, locked=False):
        return self._client.state_ctx(user=user, version=version, locked=locked)


    @init_checker
    def status(self):
        return self._client.status()

    @init_checker
    def users(self):
        return self._client.users()

    #
    #   Pullers
    #

    @init_checker
    @make_ro_state
    def fill_structs(self, user=None, state=None):
        """
        Grab all the structs from a specified user, then fill them locally

        @param user:
        @param state:
        @return:
        """
        # sanity check, the desired user has some structs to sync
        pulled_structs: List[Struct] = self.pull_structs(user=user, state=state)
        if len(pulled_structs) <= 0:
            print(f"[Binsync]: User {user} has no structs to sync!")
            return 0

        # convert each binsync struct into an ida struct and updated it
        for struct in pulled_structs:
            compat.update_struct(struct, self)

    @init_checker
    @make_ro_state
    def fill_function(self, ida_func, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @ida_func.
        """

        # == function name === #
        _func = self.pull_function(ida_func, user=user, state=state)
        if _func is None:
            return

        if compat.get_func_name(ida_func.start_ea) != _func.name:
            compat.set_ida_func_name(ida_func.start_ea, _func.name)

        # === comments === #
        # set the func comment
        func_comment = self.pull_comment(_func.addr, user=user, state=state)
        if func_comment is None:
            func_comment = ""
            #idc.set_func_cmt(_func.addr, func_comment, 1)
            #compat.set_ida_comment(_func.addr, func_comment, 1, func_cmt=True)

        # set the disassembly comments
        func_cmt_end = "\n"
        for start_ea, end_ea in idautils.Chunks(ida_func.start_ea):
            for head in idautils.Heads(start_ea, end_ea):
                if head == _func.addr:
                    continue

                comment = self.pull_comment(head, user=user, state=state)
                if comment is not None:
                    func_cmt_end += f"\n{hex(head)}: {comment}"
                    #compat.set_decomp_comments(_func.addr, {head: comment})
                    #compat.set_ida_comment(head, comment, 0, func_cmt=False)
        func_comment += func_cmt_end

        # apply a full function comment only if we have things to write.
        if len(func_comment) > 0:
            compat.set_ida_comment(_func.addr, func_comment, 1, func_cmt=True)

        # === stack variables === #
        existing_stack_vars = { }
        frame = idaapi.get_frame(ida_func.start_ea)
        if frame is None or frame.memqty <= 0:
            _l.debug("Function %#x does not have an associated function frame. Skip variable name sync-up.",
                     ida_func.start_ea)
            return

        frame_size = idc.get_struc_size(frame)
        last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))

        for i in range(frame.memqty):
            member = frame.get_member(i)
            stack_offset = member.soff - frame_size + last_member_size
            existing_stack_vars[stack_offset] = member

        for offset, stack_var in self.pull_stack_variables(ida_func, user=user, state=state).items():
            ida_offset = stack_var.get_offset(StackOffsetType.IDA)
            # skip if this variable already exists
            if ida_offset in existing_stack_vars:
                type_str = self._get_type_str(existing_stack_vars[ida_offset].flag)
            else:
                type_str = None

            if ida_offset in existing_stack_vars:
                if idc.get_member_name(frame.id, existing_stack_vars[ida_offset].soff) == stack_var.name \
                        and type_str is not None \
                        and stack_var.type == type_str:
                    continue
                # rename the existing variable
                idaapi.set_member_name(frame, existing_stack_vars[ida_offset].soff, stack_var.name)
                # TODO: retype the existing variable

        # ===== update the psuedocode ==== #
        compat.refresh_pseudocode_view(_func.addr)

    def sync_all(self, user=None, state=None):
        """
        TODO: to fix time overwrites
        Idea:
        How to fix overwritten times from hooks:
        Make a semaphore. Increment the semaphore before each action that triggers a hook.
        In the hook, decrement the semaphore. When the semaphore is 0, reset all the times
        in the state AND all commiting. Stop commiting until semaphores are done.

        Cache money.
        """

        self._client.sync_states(user=user)
        func_addrs = self._client.state.functions.keys()
        print("[Binsync]: Target Addrs for sync:", [hex(x) for x in func_addrs])

        for addr in func_addrs:
            ida_func = idaapi.get_func(addr)
            self.fill_function(ida_func, self._client.master_user) # semaphore inc

    @init_checker
    @make_ro_state
    def pull_function(self, ida_func, user=None, state=None):
        """
        Pull a function downwards.

        :param bv:
        :param bn_func:
        :param user:
        :return:
        """

        # pull function
        try:
            func: Function = state.get_function(int(ida_func.start_ea))
            return func
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_stack_variables(self, ida_func, user=None, state=None):
        try:
            return dict(state.get_stack_variables(ida_func.start_ea))
        except KeyError:
            return { }

    @init_checker
    @make_ro_state
    def pull_stack_variable(self, ida_func, offset, user=None, state=None):
        return state.get_stack_variable(ida_func.start_ea, offset)

    @init_checker
    @make_ro_state
    def pull_comment(self, addr, user=None, state=None):
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
    def pull_structs(self, user=None, state=None):
        """
        Pull structs downwards.

        @param user:
        @param state:
        @return:
        """
        return state.get_structs()



    @init_checker
    @make_state
    def remove_all_comments(self, ida_func, user=None, state=None):
        for start_ea, end_ea in idautils.Chunks(ida_func):
            for ins_addr in idautils.Heads(start_ea, end_ea):
                if ins_addr in state.comments:
                    state.remove_comment(ins_addr)

    #
    #   Pushers
    #

    @init_checker
    @make_state
    @last_push
    def push_func_comment(self, attr_addr, comment, user=None, state=None, api_set=False):
        # just push a functions comment, overwriting it
        state.set_comment(attr_addr, comment)

    @init_checker
    @make_state
    @last_push
    def push_comment(self, attr_addr, comment, user=None, state=None, api_set=False):
        # check if the function exist
        # if not; create it
        # if it does; write to the last_push parameter

        state.set_comment(attr_addr, comment)

    @init_checker
    @make_state
    @last_push
    def push_comments(self, cmt_dict: Dict[int, str], user=None, state=None, api_set=False):
        for addr in cmt_dict:
            self.push_comment(addr, cmt_dict[addr], user=user, state=state)
        
    '''
    # TODO: Just pass along the offset. Why the whole patch ??
    @init_checker
    @make_state
    def push_patch(self, patch, user=None, state=None, api_set=False):
        # Update last pushed values
        last_push_time = int(time.time())
        last_push_func = compat.ida_func_addr(patch.offset)
        func_name = compat.get_func_name(last_push_func)

        state.set_patch(patch.offset, patch)
        self._client.last_push(last_push_func, last_push_time, func_name)
    '''

    @init_checker
    @make_state
    @last_push
    def push_function_name(self, attr_addr, new_name, user=None, state=None, api_set=False):
        # setup the new function for binsync
        func = binsync.data.Function(attr_addr)
        func.name = new_name
        state.set_function(func)

    @init_checker
    @make_state
    @last_push
    def push_stack_variable(self, attr_addr, stack_offset, name, type_str, size, user=None, state=None, api_set=False):
        # convert longs to ints
        stack_offset = int(stack_offset)
        func_addr = int(attr_addr)
        size = int(size)

        v = StackVariable(stack_offset,
                          StackOffsetType.IDA,
                          name,
                          type_str,
                          size,
                          func_addr)
        state.set_stack_variable(func_addr, stack_offset, v)

    @init_checker
    @make_state
    def push_struct(self, struct, old_name, user=None, state=None, api_set=False):
        state.set_struct(struct, old_name)


    #
    # Utils
    #

    @staticmethod
    def _get_type_str(flag):
        if idc.is_byte(flag):
            return "unsigned char"
        elif idc.is_word(flag):
            return "unsigned short"
        elif idc.is_dword(flag):
            return "unsigned int"
        elif idc.is_qword(flag):
            return "unsigned long long"
        else:
            return "unknown"

    @staticmethod
    def friendly_datetime(time_before):
        # convert
        if isinstance(time_before, int):
            dt = datetime.datetime.fromtimestamp(time_before)
        elif not isinstance(time_before, datetime.datetime):
            return " "

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
            ago = diff_days < 0
        elif diff_sec >= 60 * 60:
            s = "%d hours" % int(diff_sec / 60 / 60)
        elif diff_sec >= 60:
            s = "%d minutes" % int(diff_sec / 60)
        else:
            s = "%d seconds" % diff_sec

        s += " ago" if ago else " in the future"
        return s


def on_renamed(*args):
    pass


def on_auto_empty_finally(*args):
    pass


def get_cmt(*args):
    pass
