import logging

from PyQt5 import sip
from PyQt5.QtGui import QKeyEvent
from PyQt5 import QtCore
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import Qt

import idaapi
import ida_kernwin
import ida_hexrays
import idautils

from libbs.ui.version import set_ui_version
set_ui_version("PyQt5")
from libbs.decompilers.ida.compat import has_older_hexrays_version
from libbs.decompilers.ida.interface import IDAInterface
from libbs.decompilers.ida.compat import GenericIDAPlugin

from binsync.ui.config_dialog import ConfigureBSDialog
from binsync.ui.control_panel import ControlPanel
from binsync.controller import BSController
from binsync import __version__ as VERSION

_l = logging.getLogger(__name__)

# disable the annoying "Running Python script" wait box that freezes IDA at times
idaapi.set_script_timeout(0)


#
# Hooks for building the UI
#

class AlwaysActiveAction(idaapi.action_handler_t):
    def __init__(self, action, plugin, typ):
        super(AlwaysActiveAction, self).__init__()
        self.action = action
        self.plugin = plugin
        self.typ = typ

    def activate(self, ctx):
        self.action()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class IdaHotkeyHook(ida_kernwin.UI_Hooks):
    def __init__(self, keys_to_pass, uiptr):
        super().__init__()
        self.keys_to_pass = keys_to_pass
        self.ui = uiptr

    def preprocess_action(self, action_name):
        uie = ida_kernwin.input_event_t()
        ida_kernwin.get_user_input_event(uie)
        key_event = uie.get_source_QEvent()
        keycode = key_event.key()
        if keycode[0] in self.keys_to_pass:
            ke = QKeyEvent(QtCore.QEvent.KeyPress, keycode[0], QtCore.Qt.NoModifier)
            # send new event
            self.ui.event(ke)
            # consume the event so ida doesn't take it
            return 1
        return 0


#
# Control Panel UI
#

class ControlPanelViewWrapper(object):
    NAME = "BinSync"

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
        layout.setContentsMargins(2,2,2,2)
        self.widget.setLayout(layout)

#
# Overloaded Plugin Classes
#


class BinsyncPlugin(GenericIDAPlugin):
    """Plugin entry point. Does most of the skinning magic."""

    flags = idaapi.PLUGIN_FIX
    comment = "Syncing user changes between decompilers"

    help = "BinSync: syncing user changes between decompilers"
    wanted_name = "BinSync: Configure..."
    wanted_hotkey = "Ctrl-Shift-B"

    def __init__(self, *args, **kwargs):
        print(f"[BinSync] {VERSION} loaded!")
        super().__init__(*args, **kwargs)
        self.controller = BSController(decompiler_interface=self.interface)

    def open_config_dialog(self):
        dialog = ConfigureBSDialog(self.controller)

        dialog.dialog_uihook = IdaHotkeyHook([Qt.Key_Return, Qt.Key_Tab, Qt.Key_Backtab], dialog)
        if not dialog.dialog_uihook.hook():
            _l.warning("Failed to hook ida hotkeys for SyncConfig")

        dialog.exec_()
        dialog.dialog_uihook.unhook()
        if not self.controller.check_client():
            return

        self.controller._crashing_version = has_older_hexrays_version()
        self.open_control_panel()
        if dialog.open_magic_sync:
            #display_magic_sync_dialog(controller)
            _l.debug("Magic Sync is disabled on startup for now.")

    def open_control_panel(self):
        """
        Open the control panel view and attach it to IDA View-A or Pseudocode-A.
        """
        wrapper = ControlPanelViewWrapper(self.controller)
        if not wrapper.twidget:
            _l.info("BinSync is unable to find a widget to attach to. You are likely running headlessly")
            return None

        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST
        idaapi.display_widget(wrapper.twidget, flags)
        wrapper.widget.visible = True

        # casually open a pseudocode window, this prevents magic sync from spawning pseudocode windows
        # in weird locations upon an initial run
        func_addr = next(idautils.Functions())
        if self.controller.deci.decompiler_available:
            ida_hexrays.open_pseudocode(func_addr, ida_hexrays.OPF_NO_WAIT | ida_hexrays.OPF_REUSE)

        # then attempt to flip back to IDA View-A
        twidget = idaapi.find_widget("IDA View-A")
        if twidget is not None:
            ida_kernwin.activate_widget(twidget, True)

        target = "Functions"
        fwidget = idaapi.find_widget(target)

        if not fwidget:
            # prioritize attaching the binsync panel to a decompilation window
            target = "Pseudocode-A"
            dwidget = idaapi.find_widget(target)

            if not dwidget:
                target = "IDA View-A"

        if target == "Functions":
            idaapi.set_dock_pos(ControlPanelViewWrapper.NAME, target, idaapi.DP_INSIDE)
        else:
            # attach the panel to the found target
            idaapi.set_dock_pos(ControlPanelViewWrapper.NAME, target, idaapi.DP_RIGHT)

    def install_control_panel_action(self):
        action_id = "binsync:control_panel"
        action_desc = idaapi.action_desc_t(
            action_id,
            "BinSync: ~C~ontrol Panel",
            AlwaysActiveAction(self.open_control_panel, None, None),
            None,
            "Open the BinSync control panel",
        )
        result = idaapi.register_action(action_desc)
        if not result:
            _l.info("BinSync is unable to find a widget to attach to. You are likely running headlessly")
            return None

        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump",
            action_id,
            idaapi.SETMENU_INS,
        )
        if not result:
            _l.info("BinSync is unable to find a widget to attach to. You are likely running headlessly")
            return None

    def init(self):
        super().init()
        self.install_control_panel_action()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        super().run(arg)
        self.open_config_dialog()

    def term(self):
        if self.controller:
            self.controller.stop_worker_routines()
            del self.controller
            super().term()


class IDABSInterface(IDAInterface):
    def _init_gui_plugin(self, *args, **kwargs):
        return BinsyncPlugin(*args, name=self._plugin_name, interface=self, **kwargs)
