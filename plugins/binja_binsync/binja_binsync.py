from PySide2.QtWidgets import QVBoxLayout
from PySide2.QtCore import Qt
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

from binsync.common.ui import set_ui_version
set_ui_version("PySide2")
from binsync.common.ui.config_dialog import SyncConfig
from binsync.common.ui.control_panel import ControlPanel
from .ui_tools import find_main_window, BinjaDockWidget, create_widget
from .controller import BinjaBinSyncController
from copy import deepcopy
from binsync import data


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

"""
class CurrentFunctionNotification(BinaryDataNotification):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller

    def function_update_requested(self, view, func):
        print("function_update_requested", view, func)
        self.controller.mark_as_current_function(view, func)

    def function_updated(self, view, func):
        print("function_updated", view, func)
        self.controller.mark_as_current_function(view, func)

    def symbol_added(self, view, sym):
        print(view, sym)

    def symbol_updated(self, view, sym):
        print(view, sym)

    def symbol_removed(self, view, sym):
        print(view, sym)


def launch_binsync_configure(context):
    if context.binaryView is None:
        show_message_box(
            "No binary is loaded",
            "There is no Binary View available. Please open a binary in Binary Ninja first.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    binsync_controller.set_curr_bv(context.binaryView)

    d = SyncConfig(binsync_controller)
    d.exec_()

    # register a notification to get current functions
    # TODO: This is a bad idea since more than one functions might be updated when editing one function :/
    # notification = CurrentFunctionNotification(controller)
    # context.binaryView.register_notification(notification)


def open_info_panel(*args):
    d = InfoPanelDialog(binsync_controller)
    d.show()


class PatchDataNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._patch_number = 0

    def data_written(self, view, offset, length):
        # TODO think about the naming

        file_offset = offset - view.start
        obj_name = os.path.basename(view.file.original_filename)
        patch = Patch(obj_name, file_offset, view.read(offset, length))
        self._patch_number += 1
        self._controller.push_patch(patch)


class EditFunctionNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller

    def function_updated(self, view, func):
        self._controller.push_function_header(func)


def start_patch_monitor(view):
    notification = PatchDataNotification(view, binsync_controller)
    view.register_notification(notification)


def start_function_monitor(view):
    notification = EditFunctionNotification(view, binsync_controller)
    view.register_notification(notification)
"""
class FunctionNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._function_requested = None
        self._function_saved = None

    def function_updated(self, view, func):
        # g_function_requested == func.start
        # if so push this func
        # else exit earlier
        # g_function_requested = None
        # use push function header
        if self._function_requested == func.start:
            print(f"[BinSync] Function {func.start:#x} matched request function pushing")
            self._function_requested = None
            self._controller.push_function_header(func.start, func.name)

            # Check return type
            if self._function_saved.header.ret_type != func.return_type.get_string_before_name():
                before = self._function_saved.header.ret_type
                after = func.return_type.get_string_before_name()
                print(f"[BinSync] Function {func.start:#x} detected return type change from {before} to {after}") 

            # Check arguments
            for key, value in self._function_saved.header.args.items():
                old_arg = value
                try:
                    new_arg = func.parameter_vars[key]
                except KeyError:
                    new_arg = None
                    print(f"[BinSync Function {func.start:#x} detected argument {key} removed")
                    break

                if old_arg.name != new_arg.name:
                    print(f"[BinSync] Function {func.start:#x} detected argument {key} name change from {old_arg.name} to {new_arg.name}")

                if old_arg.type_str != new_arg.type.get_string_before_name():
                    print(f"[BinSync] Function {func.start:#x} detected argument {key} type change from {old_arg.type_str} to {new_arg.type.get_string_before_name()}")

            self._function_saved = None

    def function_update_requested(self, view, func):
        # Only get one notification but promised to happen
        # g_function_requested = func.start
        # Save function copy for diff in function_update
        if self._function_requested == None:
            print(f"[BinSync] Function requested {func.start:#x}")
            self._function_requested = func.start

            # Copy function over to binsync function
            args = {}
            for i, parameter in enumerate(func.parameter_vars):
                args[i] = data.FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), 0)

            self._function_saved = data.Function(func.start, header=data.FunctionHeader(func.name, func.start, ret_type=func.return_type.get_string_before_name(), args=args))


class DataNotification(BinaryDataNotification):
    def __init__(self, view, controller):
        super().__init__()
        self._view = view
        self._controller = controller
        self._function_requested = None

    def data_var_updated(self, view, var):
        print(f"[BinSync] Data Updated Var: {var}, Type: {type(var)}")


def start_function_monitor(view, controller):
    notification = FunctionNotification(view, controller)
    view.register_notification(notification)

def start_data_monitor(view, controller):
    notification = DataNotification(view, controller)
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
        print(f"[BinSync] Starting data hook")
        start_data_monitor(bv, self.controllers[bv])

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