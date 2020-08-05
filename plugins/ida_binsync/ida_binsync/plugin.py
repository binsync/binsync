from __future__ import absolute_import, division, print_function

import os
import time

import IPython
from PyQt5.Qt import qApp
from PyQt5.QtCore import QObject, QDir
from PyQt5.QtWidgets import QMessageBox
import idaapi
import idc

import binsync
from binsync.data import Patch

from ida_binsync import IDA_DIR, VERSION
from ida_binsync.reposelector import RepoSelector, UserSelector
from ida_binsync.controller import BinsyncController
from ida_binsync.config_dialog import ConfigDialog
from ida_binsync.control_panel import ControlPanelViewWrapper


controller = BinsyncController()


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


class IDAActionHandler(idaapi.action_handler_t):
    def __init__(self, action, plugin, typ):
        super(IDAActionHandler, self).__init__()
        self.action = action
        self.plugin = plugin
        self.typ = typ

    def activate(self, ctx):
        if self.action is not None:
            self.action()
            return 1

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

    def open_config_dialog(self):
        dialog = ConfigDialog(controller)
        dialog.exec_()

        print(controller._client)

    def open_control_panel(self):
        """
        Open the control panel view and attach it to IDA View-A or Pseudocode-A.
        """

        wrapper = ControlPanelViewWrapper(controller)
        if not wrapper.twidget:
            raise RuntimeError("Unexpected: twidget does not exist.")

        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST
        idaapi.display_widget(wrapper.twidget, flags)
        wrapper.widget.visible = True

        # Dock it
        for target in ["IDA View-A", "Pseudocode-A"]:
            dwidget = idaapi.find_widget(target)
            if dwidget:
                idaapi.set_dock_pos(ControlPanelViewWrapper.NAME, target, idaapi.DP_RIGHT)
                break

    def install_actions(self):
        self.install_control_panel_action()
        # action_open = idaapi.register_action(
        #     idaapi.action_desc_t(
        #         "binsync:test",
        #         "Start Sharing Patches",
        #         custom_action_handler_t(self, "func"),
        #     )
        # )

    def install_control_panel_action(self):
        action_id = "binsync:control_panel"
        action_desc = idaapi.action_desc_t(
            action_id,
            "~C~ontrol Panel",
            IDAActionHandler(self.open_control_panel, None, None),
            None,
            "Open the BinSync control panel",
        )
        result = idaapi.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register the control panel action.")

        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump",
            action_id,
            idaapi.SETMENU_INS,
        )
        if not result:
            raise RuntimeError("Failed to attach the menu item for the control panel action.")

    def init(self):
        self.install_actions()

        self.hook1 = UiHooks()

        self.hook1.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("RUN CALLED")
        self._repo_selector = None
        self.open_config_dialog()

    def term(self):
        print("term() called!")



