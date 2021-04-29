from __future__ import absolute_import
from functools import wraps
import re
import threading
import time
import datetime
import logging
from typing import Dict, List, Tuple

import ida_hexrays
import idc
import idaapi
import idautils

from PyQt5.QtWidgets import QMessageBox

import binsync
from binsync import Client
from binsync.data import StackVariable, StackOffsetType, Function
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
            with self.state_ctx(user=user) as state:
                kwargs['state'] = state
                r = f(self, *args, **kwargs)

                self.save_lock.acquire()
                state.save()
                time.sleep(1)
                self.save_lock.release()

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
        function_callback,
        comment_callback,
        patch_callback,
        remote="origin",
        branch="master",
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
            remote=remote,
            branch=branch,
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

        # last push
        self.last_push = None

        # lock
        self.save_lock = threading.Lock()


        # start the worker routine
        self.worker_thread = threading.Thread(target=self.worker_routine)
        self.worker_thread.setDaemon(True)
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
        self._client = BinsyncClient(user, path, None, None, None, init_repo=init_repo, ssh_agent_pid=ssh_agent_pid,
                                      ssh_auth_sock=ssh_auth_sock)

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
    def push_func_comment(self, func_addr, comment, user=None, state=None):
        # just push a functions comment, overwriting it
        state.set_comment(func_addr, comment)

    @init_checker
    @make_state
    def push_comment(self, comment_addr, comment, user=None, state=None):


        # first collect the old func comment
        #try:
        #    func_cmt = state.get_comment(func_addr)
        #except KeyError:
        #    func_cmt = ""

        ## add the comment to the func comment
        #func_cmt += f"\n\n{hex(comment_addr)}: {comment}"
        #self.push_func_comment(func_addr, func_cmt, user=user, state=state)

        # also put the comment alone
        state.set_comment(comment_addr, comment)

    @init_checker
    @make_state
    def push_comments(self, cmt_dict: Dict[int, str], user=None, state=None):
        print(cmt_dict)
        for addr in cmt_dict:
            self.push_comment(addr, cmt_dict[addr], user=user, state=state)

    @init_checker
    @make_state
    def push_patch(self, patch, user=None, state=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state
    def push_function_name(self, func_addr, new_name, user=None, state=None):
        func = binsync.data.Function(func_addr)
        func.name = new_name
        state.set_function(func)

    @init_checker
    @make_state
    def push_stack_variable(self, func_addr, stack_offset, name, type_str, size, user=None, state=None):
        # convert longs to ints
        stack_offset = int(stack_offset)
        func_addr = int(func_addr)
        size = int(size)

        v = StackVariable(stack_offset,
                          StackOffsetType.IDA,
                          name,
                          type_str,
                          size,
                          func_addr)
        state.set_stack_variable(func_addr, stack_offset, v)


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


def on_renamed(*args):
    pass


def on_auto_empty_finally(*args):
    pass


def get_cmt(*args):
    pass
