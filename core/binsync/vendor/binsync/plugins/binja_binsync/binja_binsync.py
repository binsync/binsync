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
from binaryninja import PluginCommand, BinaryView, SymbolType
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.binaryview import BinaryDataNotification

from collections import defaultdict
import logging

from ....binsync.common.ui.version import set_ui_version
set_ui_version("PySide6")
from .... import binsync
from ....binsync.common.ui.config_dialog import SyncConfig
from ....binsync.common.ui.control_panel import ControlPanel
from .ui_tools import find_main_window, BinjaDockWidget, create_widget
from .controller import BinjaBinSyncController
from copy import deepcopy
from ....binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, FunctionArgument, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct
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


def conv_func_binja_to_binsync(binja_func):

    #
    # header: name, ret type, args
    #
    
    args = {
        i: FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), parameter.type.width)
        for i, parameter in enumerate(binja_func.parameter_vars)
    }

    sync_header = FunctionHeader(
        binja_func.name,
        binja_func.start,
        ret_type=binja_func.return_type.get_string_before_name(),
        args=args
    )

    #
    # stack vars
    #

    binja_stack_vars = {
        v.storage: v for v in binja_func.stack_layout if v.source_type == VariableSourceType.StackVariableSourceType
    }
    sorted_stack = sorted(binja_func.stack_layout, key=lambda x: x.storage)
    var_sizes = {}

    for off, var in binja_stack_vars.items():
        i = sorted_stack.index(var)
        if i + 1 >= len(sorted_stack):
            var_sizes[var] = 0
        else:
            var_sizes[var] = var.storage - sorted_stack[i].storage

    bs_stack_vars = {
        off: binsync.StackVariable(
            off, binsync.StackOffsetType.BINJA,
            var.name,
            var.type.get_string_before_name(),
            var_sizes[var],
            binja_func.start
        )
        for off, var in binja_stack_vars.items()
    }

    size = binja_func.address_ranges[0].end - binja_func.address_ranges[0].start
    return Function(binja_func.start, size, header=sync_header, stack_vars=bs_stack_vars)


class FunctionNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._function_requested = None
        self._function_saved = None

    def function_updated(self, view, func_):
        if self._controller.sync_lock.locked():
            return

        # Service requested function only
        if self._function_requested == func_.start:
            #print(f"[BinSync] Servicing function: {func_.start:#x}")
            # Found function clear request
            self._function_requested = None

            # Convert to binsync Function type for diffing
            func = view.get_function_at(func_.start)
            bs_func = conv_func_binja_to_binsync(func)

            #
            # header
            #
            # note: function name done inside symbol update hook
            #

            # Check return type
            if self._function_saved.header.ret_type != bs_func.header.ret_type:
                self._controller.schedule_job(
                    self._controller.push_artifact,
                    bs_func.header
                )
                
            # Check arguments
            arg_changed = False
            for key, old_arg in self._function_saved.header.args.items():
                try:
                    new_arg = bs_func.header.args[key]
                except KeyError:
                    arg_changed = True
                    break

                if old_arg.name != new_arg.name:
                    arg_changed = True
                    break

                if old_arg.type_str != new_arg.type_str:
                    arg_changed = True
                    break

            if arg_changed:
                self._controller.schedule_job(
                    self._controller.push_artifact,
                    bs_func.header
                )

            #
            # stack vars
            #

            for off, var in self._function_saved.stack_vars.items():
                if off in bs_func.stack_vars and var != bs_func.stack_vars[off]:
                    new_var = bs_func.stack_vars[off]
                    if re.match(r"var_\d+[_\d+]{0,1}", new_var.name) \
                            or new_var.name in {'__saved_rbp', '__return_addr',}:
                        continue

                    self._controller.schedule_job(
                        self._controller.push_artifact,
                        new_var
                    )

            self._function_saved = None

    def function_update_requested(self, view, func):
        if not self._controller.sync_lock.locked() and self._function_requested is None:
            #print(f"[BinSync] Function requested {func.start:#x}")
            self._function_requested = func.start
            self._function_saved = conv_func_binja_to_binsync(func)
    
    def symbol_updated(self, view, sym):
        if self._controller.sync_lock.locked():
            return

        if sym.type == SymbolType.FunctionSymbol:
            func = view.get_function_at(sym.address)
            bs_func = conv_func_binja_to_binsync(func)
            self._controller.schedule_job(
                self._controller.push_artifact,
                FunctionHeader(sym.name, sym.address, ret_type=bs_func.header.ret_type, args=bs_func.header.args)
            )

        elif sym.type == SymbolType.DataSymbol:
            pass


class DataNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._function_requested = None

    def data_var_updated(self, view, var):
        print(f"[BinSync] Data Updated Var: {var}, Type: {type(var)}")


class StructNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller

    def type_defined(self, view:'BinaryView', name:'_types.QualifiedName', type:'_types.Type') -> None:
        print(f"[BinSync] Type defined!")

    def type_undefined(self, view:'BinaryView', name:'_types.QualifiedName', type:'_types.Type') -> None:
        print(f"[BinSync] Type undefined!")


def start_function_monitor(view, controller):
    notification = FunctionNotification(view, controller)
    view.register_notification(notification)

def start_data_monitor(view, controller):
    notification = DataNotification(view, controller)
    view.register_notification(notification)

def start_struct_monitor(view, controller):
    notification = StructNotification(view, controller)
    view.register_notification(notification)


class BinjaPlugin:
    def __init__(self):
        # controller stored by a binary view
        self.controllers = defaultdict(BinjaBinSyncController)
        self._init_ui()

    def _init_ui(self):
        # config dialog
        configure_binsync_id = "BinSync: Configure"
        UIAction.registerAction(configure_binsync_id)
        UIActionHandler.globalActions().bindAction(
            configure_binsync_id, UIAction(self._launch_config)
        )
        Menu.mainMenu("Tools").addAction(configure_binsync_id, "BinSync")

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
        l.debug(f"Starting function hook")
        start_function_monitor(bv, self.controllers[bv])
        #Creates to much noise removing for time being
        #print(f"[BinSync] Starting data hook")
        #start_data_monitor(bv, self.controllers[bv])
        #print(f"[BinSync Starting struct hook")
        #start_struct_monitor(bv, self.controllers[bv])

    def _launch_config(self, bn_context):
        bv = bn_context.binaryView
        controller_bv = self.controllers[bv]

        # exit early if we already configed
        if controller_bv.bv is not None or bv is None:
            return
        controller_bv.bv = bv

        # configure
        dialog = SyncConfig(controller_bv)
        dialog.exec_()

        # if the config was successful init a full client
        if controller_bv.check_client():
            self._init_bv_dependencies(bv)


BinjaPlugin()

"""
PluginCommand.register(
    "Start Sharing Patches", "Start Sharing Patches", start_patch_monitor
)
PluginCommand.register(
    "Start Sharing Functions", "Start Sharing Functions", start_function_monitor
)
"""
