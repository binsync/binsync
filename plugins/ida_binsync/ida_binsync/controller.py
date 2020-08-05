from __future__ import absolute_import
from functools import wraps

from PyQt5.QtWidgets import QMessageBox

import binsync
from binsync import Client


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

    def current_function(self):
        # TODO:
        return None

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

    @init_checker
    def users(self):
        return self._client.users()

    def push_function(self, func_name, func_addr):
        if not self.check_client():
            return

        # Push function
        func = binsync.data.Function(func_addr)  # force conversion from long to int
        func.name = func_name
        self._client.get_state().set_function(func)

        # Push comments

        # TODO: Fixme
        self._client.save_state()

    def push_comment(self, comment_addr, comment):
        self._client.get_state().set_comment(comment_addr, comment)
        self._client.save_state()

    def push_patch(self, patch):
        if not self.check_client():
            return
        self._client.get_state().set_patch(patch.offset, patch)
        self._client.save_state()


def on_renamed(*args):
    pass


def on_auto_empty_finally(*args):
    pass


def get_cmt(*args):
    pass
