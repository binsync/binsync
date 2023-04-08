import threading
import re

from PySide6.QtWidgets import QVBoxLayout
from PySide6.QtCore import Qt
from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja.types import StructureType, EnumerationType
from binaryninja import PluginCommand, BinaryView, SymbolType
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.binaryview import BinaryDataNotification

from collections import defaultdict
import logging

from binsync.common.ui.version import set_ui_version
set_ui_version("PySide6")
from binsync.common.ui.config_dialog import ConfigureBSDialog
from binsync.common.ui.control_panel import ControlPanel
from .compat import bn_enum_to_bs, find_main_window, BinjaDockWidget, create_widget, bn_struct_to_bs, bn_func_to_bs
from .controller import BinjaBinSyncController
from binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, FunctionArgument, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct, StructMember
)

l = logging.getLogger(__name__)

#
# Binja UI
#


class ControlPanelDockWidget(BinjaDockWidget):
    def __init__(self, controller, parent=None, name=None, data=None):
        super().__init__(name, parent=parent)
        self.data = data
        print(data)
        self._widget = None
        self.controller = controller

        self._init_widgets()

    def _init_widgets(self):
        self._widget = ControlPanel(self.controller)

        layout = QVBoxLayout()
        layout.addWidget(self._widget)
        self.setLayout(layout)


#
# Other
#

def instance():
    main_window = find_main_window()
    try:
        dock = [x for x in main_window.children() if isinstance(x, BinjaDockWidget)][0]
    except:
        dock = BinjaDockWidget("dummy")
    return dock

#
# Hooks (callbacks)
#


class DataMonitor(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._func_addr_requested = None
        self._func_before_change = None

    def function_updated(self, view, func_):
        if self._controller.sync_lock.locked():
            return

        # service requested function only
        if self._func_addr_requested == func_.start:
            l.debug(f"Update on {hex(self._func_addr_requested)} being processed...")
            self._func_addr_requested = None

            # convert to binsync Function type for diffing
            bn_func = view.get_function_at(func_.start)
            bs_func = bn_func_to_bs(bn_func)

            #
            # header
            # NOTE: function name done inside symbol update hook
            #

            # check if the headers differ
            if self._func_before_change.header.diff(bs_func.header):
                self._controller.schedule_job(
                    self._controller.push_artifact,
                    bs_func.header
                )
                
            #
            # stack vars
            #

            for off, var in self._func_before_change.stack_vars.items():
                if off in bs_func.stack_vars and var != bs_func.stack_vars[off]:
                    new_var = bs_func.stack_vars[off]
                    if re.match(r"var_\d+[_\d+]{0,1}", new_var.name) \
                            or new_var.name in {'__saved_rbp', '__return_addr',}:
                        continue

                    self._controller.schedule_job(
                        self._controller.push_artifact,
                        new_var
                    )

            self._func_before_change = None

    def function_update_requested(self, view, func):
        if not self._controller.sync_lock.locked() and self._func_addr_requested is None:
            l.debug(f"Update on {func} requested...")
            self._func_addr_requested = func.start
            self._func_before_change = bn_func_to_bs(func)
    
    def symbol_updated(self, view, sym):
        if self._controller.sync_lock.locked():
            return

        l.debug(f"Symbol update Requested on {sym}...")
        if sym.type == SymbolType.FunctionSymbol:
            l.debug(f"   -> Function Symbol")
            func = view.get_function_at(sym.address)
            bs_func = bn_func_to_bs(func)
            self._controller.schedule_job(
                self._controller.push_artifact,
                FunctionHeader(sym.name, sym.address, type_=bs_func.header.type, args=bs_func.header.args)
            )
        elif sym.type == SymbolType.DataSymbol:
            l.debug(f"   -> Data Symbol")
            var: binaryninja.DataVariable = view.get_data_var_at(sym.address)
            
            self._controller.schedule_job(
                self._controller.push_artifact,
                GlobalVariable(var.address, var.name, type_=str(var.type), size=var.type.width)
            )
        else:
            l.debug(f"   -> Other Symbol: {sym.type}")
            pass

    def type_defined(self, view, name, type_):
        l.debug(f"Type Defined: {name} {type_}")
        if self._controller.sync_lock.locked():
            return 
        
        if isinstance(type_, StructureType):
            bs_struct = bn_struct_to_bs(name, type_)
            self._controller.schedule_job(
                self._controller.push_artifact,
                bs_struct
            )

        elif isinstance(type_, EnumerationType):
            bs_enum = bn_enum_to_bs(type_)
            self._controller.schedule_job(self._controller.push_artifact, bs_enum)


def start_data_monitor(view, controller):
    notification = DataMonitor(view, controller)
    view.register_notification(notification)


class BinjaPlugin:
    def __init__(self):
        # controller stored by a binary view
        self.controllers = defaultdict(BinjaBinSyncController)
        self._init_ui()

    def _init_ui(self):
        # config dialog
        configure_binsync_id = "BinSync: Configure..."
        UIAction.registerAction(configure_binsync_id)
        UIActionHandler.globalActions().bindAction(
            configure_binsync_id, UIAction(self._launch_config)
        )
        Menu.mainMenu("Plugins").addAction(configure_binsync_id, "BinSync")

        # control panel (per BV)
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.addDockWidget(
            "BinSync: Control Panel",
            lambda n, p, d: create_widget(ControlPanelDockWidget, n, p, d, self.controllers),
            Qt.RightDockWidgetArea,
            Qt.Vertical,
            True
        )

    def _init_bv_dependencies(self, bv):
        l.debug(f"Starting data hook")
        start_data_monitor(bv, self.controllers[bv])

    def _launch_config(self, bn_context):
        bv = bn_context.binaryView
        controller_bv = self.controllers[bv]

        # exit early if we already configed
        if (controller_bv.bv is not None and controller_bv.check_client()) or bv is None:
            l.info("BinSync has already been configured! Restart if you want to reconfigure.")
            return

        controller_bv.bv = bv
        # configure
        dialog = ConfigureBSDialog(controller_bv)
        dialog.exec_()

        # if the config was successful init a full client
        if controller_bv.check_client():
            self._init_bv_dependencies(bv)


BinjaPlugin()
