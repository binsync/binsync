# ----------------------------------------------------------------------------
# This file is simply the entrypoint from the initial call in ida_binsync,
# which will setup all the hooks for both the UI and IDB changes, and will
# also create the config window.
#
# ----------------------------------------------------------------------------

import os

from PyQt5 import sip
from PyQt5.QtCore import QObject

import idaapi
import idc
import ida_idp
from PyQt5.QtWidgets import QWidget, QVBoxLayout

from binsync.common.ui import set_ui_version
set_ui_version("PyQt5")
from binsync.common.ui.config_dialog import SyncConfig
from binsync.common.ui.control_panel import ControlPanel

from .hooks import MasterHook
from . import IDA_DIR, VERSION
from .controller import IDABinSyncController

controller = IDABinSyncController()

# disable the annoying "Running Python script" wait box that freezes IDA at times
idaapi.set_script_timeout(0)


#
#   UI Hook, placed here for convenience of reading UI implementation
#


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

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



#
# Control Panel
#

class ControlPanelViewWrapper(object):
    NAME = "BinSync: Info Panel"

    def __init__(self, controller):
        # create a dockable view
        self.twidget = idaapi.create_empty_widget(ControlPanelViewWrapper.NAME)
        self.widget = sip.wrapinstance(int(self.twidget), QWidget)
        self.widget.name = ControlPanelViewWrapper.NAME
        self.width_hint = 250

        self._controller = controller
        self._w = None

        self._init_widgets()

    def _init_widgets(self):
        self._w = ControlPanel(self._controller)
        layout = QVBoxLayout()
        layout.addWidget(self._w)
        self.widget.setLayout(layout)

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

    def open_config_dialog(self):
        dialog = SyncConfig(controller)
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
        # Hook UI Startup in IDA
        self.install_actions()
        self.ui_hook = UiHooks()
        self.ui_hook.hook()

        # Hook IDB & Decomp Actions in IDA
        self.action_hooks = MasterHook(controller)
        self.action_hooks.hook()

    def init(self):
        self._init_hooks()

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


def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    plugin_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(
        plugin_path,
        resource_name
    )




