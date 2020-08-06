from __future__ import absolute_import
from functools import wraps
import re
import logging

from PyQt5.QtWidgets import QMessageBox
import idc
import idaapi
import idautils

import binsync
from binsync import Client
from binsync.data import StackVariable, StackOffsetType

_l = logging.getLogger(name=__name__)


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if not self.check_client():
            raise ValueError("Please connect to a repo first.")
        return f(self, *args, **kwargs)
    return initcheck


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

    def connect(self, user, path, init_repo):
        self._client = BinsyncClient(user, path, None, None, None, init_repo=init_repo)

    def check_client(self):
        if self._client is None:
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
        ea = idc.ScreenEA()
        func = idaapi.get_func(ea)
        return func

    @init_checker
    def users(self):
        return self._client.users()

    @init_checker
    def push_function(self, ida_func):
        # Push function
        func_addr = int(ida_func.start_ea)
        func = binsync.data.Function(func_addr)
        func.name = idc.GetFunctionName(func_addr)
        self._client.get_state().set_function(func)
        self._client.save_state()

    @init_checker
    def pull_function(self, ida_func, user=None):
        """
        Pull a function downwards.

        :param bv:
        :param bn_func:
        :param user:
        :return:
        """
        state = self._client.get_state(user=user)

        # pull function
        try:
            func = state.get_function(int(ida_func.start_ea))
            return func
        except KeyError:
            return None

    @init_checker
    def fill_function(self, ida_func, user=None):
        """
        Grab all relevant information from the specified user and fill the @ida_func.
        """

        _func = self.pull_function(ida_func, user=user)
        if _func is None:
            return

        # name
        if idc.GetFunctionName(ida_func.start_ea) != _func.name:
            idaapi.set_name(ida_func.start_ea, _func.name, idaapi.SN_FORCE)

        # comments
        for start_ea, end_ea in idautils.Chunks(ida_func.start_ea):
            for head in idautils.Heads(start_ea, end_ea):
                comment = self.pull_comment(head, user=user)
                if comment is not None:
                    idc.MakeRptCmt(head, comment)

        # stack variables
        existing_stack_vars = { }

        frame = idaapi.get_frame(ida_func.start_ea)
        if frame is None or frame.memqty <= 0:
            _l.debug("Function %#x does not have an associated function frame. Skip variable name sync-up.",
                     ida_func.start_ea)
            return

        frame_size = idc.GetStrucSize(frame)
        last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))

        for i in range(frame.memqty):
            member = frame.get_member(i)
            stack_offset = member.soff - frame_size + last_member_size
            existing_stack_vars[stack_offset] = member

        for offset, stack_var in self.pull_stack_variables(ida_func, user=user).items():
            ida_offset = stack_var.get_offset(StackOffsetType.IDA)
            # skip if this variable already exists
            if ida_offset in existing_stack_vars:
                type_str = self._get_type_str(existing_stack_vars[ida_offset].flag)
            else:
                type_str = None

            if ida_offset in existing_stack_vars:
                if idc.GetMemberName(frame.id, existing_stack_vars[ida_offset].soff) == stack_var.name \
                        and type_str is not None \
                        and stack_var.type == type_str:
                    continue
                # rename the existing variable
                idaapi.set_member_name(frame, existing_stack_vars[ida_offset].soff, stack_var.name)
                # TODO: retype the existing variable

    @init_checker
    def push_comments(self, comments):
        # Push comments
        for addr, comment in comments.items():
            comm_addr = int(addr)
            self._client.get_state().set_comment(comm_addr, comment)

        # TODO: Fixme
        self._client.save_state()

    @init_checker
    def push_comment(self, comment_addr, comment):
        self._client.get_state().set_comment(comment_addr, comment)
        self._client.save_state()

    @init_checker
    def pull_comment(self, addr, user=None):
        """
        Pull comments downwards.

        :param bv:
        :param start_addr:
        :param end_addr:
        :param user:
        :return:
        """
        state = self._client.get_state(user=user)
        try:
            return state.get_comment(addr)
        except KeyError:
            return None

    def push_patch(self, patch):
        if not self.check_client():
            return
        self._client.get_state().set_patch(patch.offset, patch)
        self._client.save_state()

    @init_checker
    def push_stack_variable(self, ida_func, stack_offset, name, type_str, size):
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
        self._client.get_state().set_stack_variable(func_addr, stack_offset, v)

    @init_checker
    def push_stack_variables(self, ida_func):

        frame = idaapi.get_frame(ida_func.start_ea)
        if frame is None or frame.memqty <= 0:
            _l.debug("Function %#x does not have an associated function frame.", ida_func.start_ea)
            return

        # compute frame size
        frame_size = idc.GetStrucSize(frame)
        last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))

        for i in range(frame.memqty):
            member = frame.get_member(i)
            name = idc.GetMemberName(frame.id, member.soff)

            # ignore all unnamed variables
            # TODO: Do not ignore re-typed but unnamed variables
            if re.match(r"var_\d+", name) or name in {
                ' s', ' r',
            }:
                continue

            stack_offset = member.soff - frame_size + last_member_size
            size = idaapi.get_member_size(member)
            type_str = self._get_type_str(member.flag)
            self.push_stack_variable(ida_func, stack_offset, name, type_str, size)

        self._client.save_state()

    @init_checker
    def pull_stack_variables(self, ida_func, user=None):
        state = self._client.get_state(user=user)
        try:
            return dict(state.get_stack_variables(ida_func.start_ea))
        except KeyError:
            return { }

    @init_checker
    def pull_stack_variable(self, ida_func, offset, user=None):
        state = self._client.get_state(user=user)
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
