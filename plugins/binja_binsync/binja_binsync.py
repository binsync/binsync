import os
import re
import time
import threading
import datetime
from functools import wraps
from typing import Optional, Iterable, Dict, Any
import logging

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
from binaryninja.binaryview import BinaryDataNotification, BinaryViewType
from collections import defaultdict
import binsync
from binsync import State, StateContext
from binsync.data import Patch, Function, Comment, StackVariable, StackOffsetType

from .controller import BinsyncController
from .ui.ui_tools import find_main_window, BinjaDockWidget, create_widget
from .ui.config_dialog import SyncConfig
from .ui.info_panel import InfoPanelDialog, InfoPanelDockWidget

binsync_controller_by_bv = defaultdict(BinsyncController)


def instance():
    main_window = find_main_window()
    try:
        dock = [x for x in main_window.children() if isinstance(x, BinjaDockWidget)][0]
    except:
        dock = BinjaDockWidget("dummy")
    return dock


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

    controller = binsync_controller_by_bv[context.binaryView]
    controller.set_curr_bv(context.binaryView)

    d = SyncConfig(controller)
    d.exec_()

    # register a notification to get current functions
    # TODO: This is a bad idea since more than one functions might be updated when editing one function :/
    # notification = CurrentFunctionNotification(controller)
    # context.binaryView.register_notification(notification)


def open_info_panel(context):
    controller = binsync_controller_by_bv[context.binaryView]
    d = InfoPanelDialog(controller)
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
        self._controller.push_function(func)


def start_patch_monitor(view):
    controller = binsync_controller_by_bv[view]
    notification = PatchDataNotification(view, controller)
    view.register_notification(notification)


def start_function_monitor(view):
    controller = binsync_controller_by_bv[view]
    notification = EditFunctionNotification(view, controller)
    view.register_notification(notification)


def bv_loaded(bv):
    controller = binsync_controller_by_bv[bv]
    assert controller.client is None
    controller.set_curr_bv(bv)
    controller.maybe_connect_from_stored_config()

BinaryViewType.add_binaryview_initial_analysis_completion_event(bv_loaded)

configure_binsync_id = "BinSync: Configure"
UIAction.registerAction(configure_binsync_id)
UIActionHandler.globalActions().bindAction(
    configure_binsync_id, UIAction(launch_binsync_configure)
)
Menu.mainMenu("Tools").addAction(configure_binsync_id, "BinSync")

open_control_panel_id = "BinSync: Open info panel"
UIAction.registerAction(open_control_panel_id)
UIActionHandler.globalActions().bindAction(
    open_control_panel_id, UIAction(open_info_panel)
)
Menu.mainMenu("Tools").addAction(open_control_panel_id, "BinSync")

# register the control panel dock widget
dock_handler = DockHandler.getActiveDockHandler()
dock_handler.addDockWidget(
    "BinSync: Info Panel",
    lambda n, p, d: create_widget(InfoPanelDockWidget, n, p, d, binsync_controller_by_bv[d]),
    Qt.RightDockWidgetArea,
    Qt.Vertical,
    True
)

#PluginCommand.register(
#    "Start Sharing Patches", "Start Sharing Patches", start_patch_monitor
#)
#PluginCommand.register(
#    "Start Sharing Functions", "Start Sharing Functions", start_function_monitor
#)
