from __future__ import absolute_import, division, print_function

import os
import time

from PyQt5.Qt import qApp
from PyQt5.QtCore import QObject, QDir
from PyQt5.QtWidgets import QMessageBox
import idaapi
import idc
import ida_idp

import binsync
from binsync.data import Patch

from ida_binsync import IDA_DIR, VERSION
from ida_binsync.controller import BinsyncController
from ida_binsync.config_dialog import ConfigDialog
from ida_binsync.control_panel import ControlPanelViewWrapper
from ida_binsync.sync_menu import SyncMenu

controller = BinsyncController()

# disable the annoying "Running Python script" wait box that freezes IDA at times
idaapi.set_script_timeout(0)

#
#   Hooks for IDP, IDB, and UI
#

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

class MoreHooks(ida_idp.IDB_Hooks):
    """
        IDB hooks, subclassed from ida_idp.py
    """

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    def area_cmt_changed(self, *args):
        """
            Function comments are Area comments
        """
        cb, area, cmt, rpt = args
        print(f"AREA COMMENT CHANGED: {cmt}")

        return ida_idp.IDB_Hooks.area_cmt_changed(self, *args)

    def renamed(self, *args):
        ea, new_name, is_local_name = args
        print(f"SOMETHING RENAMED: {new_name}")
        min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        max_ea = idc.get_inf_attr(idc.INF_MAX_EA)

        return ida_idp.IDB_Hooks.renamed(self, *args)

    def cmt_changed(self, *args):
        """
            A comment changed somewhere
        """
        addr, rpt = args
        cmt = idc.get_cmt(addr, rpt)
        print(f"COMMENT CHANGED: {cmt}")

        return ida_idp.IDB_Hooks.cmt_changed(self, *args)


class IDBHooks(idaapi.IDB_Hooks):
    def renamed(self, ea, new_name, local_name):
        print("RENAME HOOKED")
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

    def area_cmt_changed(self, *args):
        """
            Function comments are Area comments
        """
        cb, area, cmt, rpt = args
        print(f"COMMENT: {cmt}")

        return idaapi.IDB_Hooks.area_cmt_changed(self, *args)

    def extra_cmt_changed(self, ea, line_idx, repeatable):
        print("EXTRA COMMENT CHANGED IDB")
        controller.push_comment(ea, idaapi.get_cmt(ea, repeatable))
        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, repeatable)

    def area_cmt_changed(self, cb, a, cmt, repeatable):
        print("AREA COMMENT CHANGED IDB")
        # publish({'cmd': 'area_comment', 'range': [get_can_addr(a.startEA), get_can_addr(a.endEA)], 'text': cmt or ''}, send_uuid=False)
        return idaapi.IDB_Hooks.area_cmt_changed(self, cb, a, cmt, repeatable)


class UiHooks(idaapi.UI_Hooks):
    """
    UI hooks. Currently only used to display a warning when
    switching font settings in IDA.
    """

    def __init__(self):
        super(UiHooks, self).__init__()
        self._last_event = None

    def finish_populating_widget_popup(self, form, popup):
        # We'll add our action to all "IDA View-*"s.
        # If we wanted to add it only to "IDA View-A", we could
        # also discriminate on the widget's title:
        #
        #  if idaapi.get_tform_title(form) == "IDA View-A":
        #      ...
        #
        # if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(form, popup, "binsync:test", None)
        inject_binsync_actions(form, popup, idaapi.get_widget_type(form))

#
#   Action Handlers
#

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

#
#   Base Plugin
#

class BinsyncPlugin(QObject, idaapi.plugin_t):
    """Plugin entry point. Does most of the skinning magic."""

    flags = idaapi.PLUGIN_FIX
    comment = "Syncing dbs between users"

    help = "This is help"
    wanted_name = "Binsync: settings"
    wanted_hotkey = "Ctrl-Shift-B"

    def __init__(self, *args, **kwargs):
        print("[Binsync] {} loaded!".format(VERSION))

        QObject.__init__(self, *args, **kwargs)
        idaapi.plugin_t.__init__(self)


    def _init_action_sync_menu(self):
        """
        Register the sync_menu action with IDA.
        """
        menu = SyncMenu(controller)

        # describe the action
        action_desc = idaapi.action_desc_t(
            "binsync:sync_menu",                        # The action name.
            "Binsync action...",             # The action text.
            menu.ctx_menu,                          # The action handler.
            None,                                    # Optional: action shortcut
            "Select actions to sync in Binsync", # Optional: tooltip
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def open_config_dialog(self):
        dialog = ConfigDialog(controller)
        dialog.exec_()

        if controller.check_client():
            self.open_control_panel()

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

    def install_control_panel_action(self):
        action_id = "binsync:control_panel"
        action_desc = idaapi.action_desc_t(
            action_id,
            "BinSync: ~C~ontrol Panel",
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
    def _init_hooks(self):
        self.install_actions()
        self.hook1 = UiHooks()
        self.hook1.hook()

        #self.hook2 = IDBHooks()
        #self.hook2.hook()
        #self.hook3 = IDPHooks()
        #self.hook3.hook()
        self.hook4 = MoreHooks()
        self.hook4.hook()

    def init(self):
        self._init_hooks()
        self._init_action_sync_menu()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open_config_dialog()

    def term(self):
        print("term() called!")

#
#   Utils
#

def get_cursor_func_ref():
    """
    Get the function reference under the user cursor.

    Returns BADADDR or a valid function address.
    """
    current_widget = idaapi.get_current_widget()
    form_type = idaapi.get_widget_type(current_widget)
    vu = idaapi.get_widget_vdui(current_widget)

    #
    # hexrays view is active
    #

    if vu:
        cursor_addr = vu.item.get_ea()

    #
    # disassembly view is active
    #

    elif form_type == idaapi.BWN_DISASM:
        cursor_addr = idaapi.get_screen_ea()
        opnum = idaapi.get_opnum()

        if opnum != -1:

            #
            # if the cursor is over an operand value that has a function ref,
            # use that as a valid rename target
            #

            op_addr = idc.get_operand_value(cursor_addr, opnum)
            op_func = idaapi.get_func(op_addr)

            if op_func and op_func.start_ea == op_addr:
                return op_addr

    # unsupported/unknown view is active
    else:
        return idaapi.BADADDR

    #
    # if the cursor is over a function definition or other reference, use that
    # as a valid rename target
    #

    cursor_func = idaapi.get_func(cursor_addr)
    if cursor_func and cursor_func.start_ea == cursor_addr:
        return cursor_addr

    # fail
    return idaapi.BADADDR

def inject_binsync_actions(form, popup, form_type):
    """
    Inject binsync actions to popup menu(s) based on context.
    """

    #
    # disassembly window
    #

    if form_type == idaapi.BWN_DISASMS:
        if get_cursor_func_ref() == idaapi.BADADDR:
            return

        #
        # the user cursor is hovering over a valid target for a recursive
        # function prefix. insert the prefix action entry into the menu
        #

        idaapi.attach_action_to_popup(
            form,
            popup,
            "binsync:sync_menu",
            "Rename",
            idaapi.SETMENU_APP
        )

    #
    # functions window
    #

    elif form_type == idaapi.BWN_FUNCS:

        idaapi.attach_action_to_popup(
            form,
            popup,
            "binsync:sync_menu",
            "Delete function(s)...",
            idaapi.SETMENU_INS
        )

        # inject a menu separator
        idaapi.attach_action_to_popup(
            form,
            popup,
            None,
            "Delete function(s)...",
            idaapi.SETMENU_INS
        )

    # done
    return 0





