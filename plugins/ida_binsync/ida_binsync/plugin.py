from __future__ import absolute_import, division, print_function

import os

import idaapi
import idc
import time
from ida_binsync import IDA_DIR, VERSION
import binsync
import IPython
from binsync.data import Patch

from ida_binsync.reposelector import RepoSelector, UserSelector
from PyQt5.Qt import qApp
from PyQt5.QtCore import QObject, QDir
from PyQt5.QtWidgets import QMessageBox


class BinsyncClient(binsync.Client):
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


class UiHooks(idaapi.UI_Hooks):
    """
    UI hooks. Currently only used to display a warning when
    switching font settings in IDA.
    """

    def __init__(self):
        super(UiHooks, self).__init__()
        self._last_event = None

    def finish_populating_tform_popup(self, form, popup):
        # We'll add our action to all "IDA View-*"s.
        # If we wanted to add it only to "IDA View-A", we could
        # also discriminate on the widget's title:
        #
        #  if idaapi.get_tform_title(form) == "IDA View-A":
        #      ...
        #
        # if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(form, popup, "binsync:test", None)


class custom_action_handler_t(idaapi.action_handler_t):
    def __init__(self, plugin, typ):
        idaapi.action_handler_t.__init__(self)
        self.typ = typ
        self.plugin = plugin

    def activate(self, ctx):
        print("IN ACTIVATE")
        if self.typ == "func":
            self.plugin.hook2 = IDPHooks()
            self.plugin.hook3 = IDBHooks()
            self.plugin.hook2.hook()
            self.plugin.hook3.hook()
            print("FINISHED HOOKING")
            controller._client.start_auto()

        elif self.typ == "patch":
            pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class BinsyncPlugin(QObject, idaapi.plugin_t):
    """Plugin entry point. Does most of the skinning magic."""

    flags = idaapi.PLUGIN_FIX
    comment = "Syncing dbs between users"

    help = "This is help"
    wanted_name = "Binsync: settings"
    wanted_hotkey = "Ctrl-Shift-B"

    def __init__(self, *args, **kwargs):
        print("[Binsync] {} by clasm loaded!".format(VERSION))

        QObject.__init__(self, *args, **kwargs)
        idaapi.plugin_t.__init__(self)

    def open_repo_selector(self):

        was_canceled = False
        if not self._repo_selector:
            self._repo_selector = RepoSelector()
            self._repo_selector.Compile()
            ok = self._repo_selector.Execute()
            if ok == 1:
                try:
                    controller.connect(
                        self._repo_selector.user_name,
                        self._repo_selector.repo_dir,
                        self._repo_selector.init_repo,
                    )
                    self._repo_selector.Free()
                except Exception as e:
                    # self._repo_selector.display_error(type(e).__name__)
                    import sys, traceback

                    traceback.print_exc(file=sys.stdout)
                    idaapi.warning(type(e).__name__)
                    self._repo_selector.Free()
                    self._repo_selector = None
                    self.open_repo_selector()
                    return
            else:
                was_canceled = True

        if not was_canceled:
            user_select = UserSelector([x.name.encode('ascii') for x in controller._client.users()])
            user_select.Compile()
            has_selected = user_select.Execute()
            if has_selected == 1:
                print("SELECTED", user_select.selected_user)


    def init(self):
        action = idaapi.register_action(
            idaapi.action_desc_t(
                "binsync:test",
                "Start Sharing Patches",
                custom_action_handler_t(self, "func"),
            )
        )

        self.hook1 = UiHooks()

        self.hook1.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("RUN CALLED")
        self._repo_selector = None
        self.open_repo_selector()

    def term(self):
        print("term() called!")


class BinsyncController:
    def __init__(self):
        self._client = None  # type: binsync.Client

    def connect(self, user, path, init_repo):
        self._client = BinsyncClient(user, path, None, None, None, init_repo=init_repo)

    def _check_client(self):
        if self._client is None:
            self._repo_selector.display_error(
                "BinSync client does not exist\nYou haven't connected to a binsync repo. Please connect to a binsync repo first."
            )
            return False
        return True

    def push_function(self, func_name, func_addr):
        if not self._check_client():
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
        if not self._check_client():
            return
        self._client.get_state().set_patch(patch.offset, patch)
        self._client.save_state()


def on_renamed(*args):
    pass


def on_auto_empty_finally(*args):
    pass


def get_cmt(*args):
    pass


class IDPHooks(idaapi.IDP_Hooks):
    def renamed(self, ea, new_name, local_name):
        print("RENAMED IDP")
        # on_renamed(ea, new_name, local_name)
        return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)

    # TODO: make sure this is on 6.1
    def auto_empty_finally(self):
        print("AUTO EMPTY IDP")
        # on_auto_empty_finally()
        return idaapi.IDP_Hooks.auto_empty_finally(self)


class IDBHooks(idaapi.IDB_Hooks):
    def renamed(self, ea, new_name, local_name):
        controller.push_function(new_name, ea)
        # on_renamed(ea, new_name, local_name)
        return idaapi.IDB_Hooks.renamed(self, ea, new_name, local_name)

    def byte_patched(self, ea, old_value):
        print("AUTO EMPTY IDB")
        # on_auto_empty_finally()
        return idaapi.IDB_Hooks.byte_patched(self, ea, old_value)

    def auto_empty_finally(self):
        print("AUTO EMPTY IDB")
        # on_auto_empty_finally()
        return idaapi.IDB_Hooks.auto_empty_finally(self)

    def cmt_changed(self, ea, repeatable):
        print("COMMENT CHANGED IDB", idaapi.get_cmt(ea, repeatable))
        controller.push_comment(ea, idaapi.get_cmt(ea, repeatable))
        return idaapi.IDB_Hooks.cmt_changed(self, ea, repeatable)

    def extra_cmt_changed(self, ea, line_idx, repeatable):
        print("EXTRA COMMENT CHANGED IDB")
        controller.push_comment(ea, idaapi.get_cmt(ea, repeatable))
        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, repeatable)

    def area_cmt_changed(self, cb, a, cmt, repeatable):
        print("AREA COMMENT CHANGED IDB")
        # publish({'cmd': 'area_comment', 'range': [get_can_addr(a.startEA), get_can_addr(a.endEA)], 'text': cmt or ''}, send_uuid=False)
        return idaapi.IDB_Hooks.area_cmt_changed(self, cb, a, cmt, repeatable)


class UIHooks(idaapi.UI_Hooks):
    pass


controller = BinsyncController()
