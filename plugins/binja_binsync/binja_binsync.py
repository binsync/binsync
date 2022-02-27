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
from binaryninja import PluginCommand, BinaryView
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, VariableSourceType
from binaryninja.binaryview import BinaryDataNotification

from collections import defaultdict
import logging

from binsync.common.ui import set_ui_version
set_ui_version("PySide6")
from binsync.common.ui.config_dialog import SyncConfig
from binsync.common.ui.control_panel import ControlPanel
from .ui_tools import find_main_window, BinjaDockWidget, create_widget
from .controller import BinjaBinSyncController
from copy import deepcopy
from binsync import data

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
    args = {}
    for i, parameter in enumerate(binja_func.parameter_vars):
        args[i] = data.FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), 0)

    sync_header = data.FunctionHeader(binja_func.name,
                                      binja_func.start,
                                      ret_type=binja_func.return_type.get_string_before_name(),
                                      args=args)

    sync_stack_vars = None
    size = binja_func.address_ranges[0].end - binja_func.address_ranges[0].start
    return data.Function(binja_func.start, size, header=sync_header, stack_vars=sync_stack_vars)


class FunctionNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._function_requested = None
        self._function_saved = None

    def function_updated(self, view, func):
        # Service requested function only
        if self._function_requested == func.start:
            # Found function clear request
            self._function_requested = None
            # Convert to binsync Function type for diffing
            bs_func = conv_func_binja_to_binsync(func)

            # Check if name changed
            if self._function_saved.header.name != bs_func.header.name:
                before = self._function_saved.header.name
                after = bs_func.header.name
                print(f"[BinSync] Function {bs_func.addr:#x} detected name change from {before} to {after}")

            # Check return type
            if self._function_saved.header.ret_type != bs_func.header.ret_type:
                before = self._function_saved.header.ret_type
                after = bs_func.header.ret_type
                self._controller.push_function_header(bs_func.header)
                return

            # Check arguments
            for key, old_arg in self._function_saved.header.args.items():
                try:
                    new_arg = bs_func.header.args[key]
                except KeyError:
                    new_arg = None
                    print(f"[BinSync Function {bs_func.addr:#x} detected argument {key} removed")
                    break

                if old_arg.name != new_arg.name:
                    print(f"[BinSync] Function {bs_func.addr:#x} detected argument {key} name change from {old_arg.name} to {new_arg.name}")

                if old_arg.type_str != new_arg.type_str:
                    print(f"[BinSync] Function {bs_func.addr:#x} detected argument {key} type change from {old_arg.type_str} to {new_arg.type_str}")

            self._function_saved = None

    def function_update_requested(self, view, func):
        if self._function_requested is None:
            print(f"[BinSync] Function requested {func.start:#x}")
            self._function_requested = func.start
            self._function_saved = conv_func_binja_to_binsync(func)


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
        print(f"[BinSync] Starting function hook")
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
        if controller_bv.bv is not None:
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