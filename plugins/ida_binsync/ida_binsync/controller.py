from __future__ import absolute_import
from functools import wraps
import re
import threading
import time
import datetime
import logging

from PyQt5.QtWidgets import QMessageBox
import idc
import idaapi
import idautils

import binsync
from binsync import Client
from binsync.data import StackVariable, StackOffsetType

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
            save_before_return = True
            state = self._client.get_state(user=user)
        else:
            save_before_return = False
        kwargs['state'] = state
        r = f(self, *args, **kwargs)
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
        if self.get_state().dirty:
            # do a save!
            user = [x for x in self.users() if x.name == "wgibbs16"][0]
            print(user.name)
            print(user.uid)
            self.state = self.get_state(user=user)
            #self.state = self.get_state(user=)
            #for addr in state.functions.keys():
            #    print("ADDR:", addr)
            #    print("FUNC:", state.functions[addr].name)
            #    idaapi.set_name(addr, state.functions[addr].name)

            #for addr in state.comments.keys():
            #    idc.MakeRptCmt(addr, state.comments[addr].encode('ascii'))

            self.save_state()

        if self.has_remote:
            # do a push... if there is a remote
            self.push()

        self._last_commit_ts = time.time()
        # for addr in state.comments.keys():
        #    print("ADDR:", addr)
        #    print("COMMENT:", state.comments[addr])
        # idc.MakeRptCmt(addr, state.comments[addr].comment)
        # print("EXITING")


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

        self.control_panel = None

        # last push
        self.last_push = None

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

            if self.check_client() and self._client.has_remote \
                    and (
                        self.last_push is None
                        or (datetime.datetime.now() - self.last_push).seconds > 10
                        ):
                self.push_tracked_functions()


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
    @make_state
    def push_tracked_functions(self, user=None, state=None):
        funcs = state.functions
        for func in state.functions.values():
            if func.track:
                self.push_function(func, state)

    def push_function(self, binsync_func, state):
        state.set_function(binsync_func)

        """
        # get the function name
        func_addr = int(ida_func.start_ea)
        func = binsync.data.Function(func_addr)
        func.name = compat.get_func_name(func_addr)
        state.set_function(func)

        # get all the comments int the function
        for start_ea, end_ea in idautils.Chunks(func_addr):
            for head in idautils.Heads(start_ea, end_ea):
                comment = self.pull_comment(head, user=user, state=state)
                if comment is not None:
                    idc.set_func_cmt(head, comment, 1)
        """

    @init_checker
    def status(self):
        return self._client.status()

    @init_checker
    def users(self):
        return self._client.users()

    @init_checker
    @make_state
    def toggle_tracking(self, ida_func, user=None, state=None):
        # first check if the function state exists
        func_addr = int(ida_func.start_ea)
        try:
            func = state.get_function(func_addr)
        except KeyError:
            # if it does not exist, make a new one
            func = binsync.data.Function(func_addr)

        # toggle the current tracking
        func.track = not func.track

        # set other information
        func.name = compat.get_func_name(func_addr)

        if func.track:
            self.push_function(func, state)


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
            func = state.get_function(int(ida_func.start_ea))
            return func
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def fill_function(self, ida_func, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @ida_func.
        """

        _func = self.pull_function(ida_func, user=user, state=state)
        if _func is None:
            return

        # name
        if compat.get_func_name(ida_func.start_ea) != _func.name:
            idaapi.set_name(ida_func.start_ea, _func.name, idaapi.SN_FORCE)

        # comments
        for start_ea, end_ea in idautils.Chunks(ida_func.start_ea):
            for head in idautils.Heads(start_ea, end_ea):
                comment = self.pull_comment(head, user=user, state=state)
                if comment is not None:
                    idc.set_func_cmt(head, comment, 1)

        # stack variables
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

    @init_checker
    @make_state
    def remove_all_comments(self, ida_func, user=None, state=None):
        for start_ea, end_ea in idautils.Chunks(ida_func.start_ea):
            for ins_addr in idautils.Heads(start_ea, end_ea):
                if ins_addr in state.comments:
                    state.remove_comment(ins_addr)

    @init_checker
    @make_state
    def push_comments(self, comments, user=None, state=None):
        # Push comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            state.set_comment(comm_addr, comment)

    @init_checker
    @make_state
    def push_comment(self, comment_addr, comment, user=None, state=None):
        state.set_comment(comment_addr, comment)

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
    def push_patch(self, patch, user=None, state=None):
        state.set_patch(patch.offset, patch)

    @init_checker
    @make_state
    def push_stack_variable(self, ida_func, stack_offset, name, type_str, size, user=None, state=None):
        # convert longs to ints
        stack_offset = int(stack_offset)
        func_addr = int(ida_func.start_ea)
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
    def push_stack_variables(self, ida_func, user=None, state=None):

        frame = idaapi.get_frame(ida_func.start_ea)
        if frame is None or frame.memqty <= 0:
            _l.debug("Function %#x does not have an associated function frame.", ida_func.start_ea)
            return

        # compute frame size
        frame_size = idc.get_struc_size(frame)
        last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))

        for i in range(frame.memqty):
            member = frame.get_member(i)
            name = idc.get_member_name(frame.id, member.soff)

            # ignore all unnamed variables
            # TODO: Do not ignore re-typed but unnamed variables
            if re.match(r"var_\d+", name) or name in {
                ' s', ' r',
            }:
                continue

            stack_offset = member.soff - frame_size + last_member_size
            size = idaapi.get_member_size(member)
            type_str = self._get_type_str(member.flag)
            self.push_stack_variable(ida_func, stack_offset, name, type_str, size, user=user, state=state)

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
