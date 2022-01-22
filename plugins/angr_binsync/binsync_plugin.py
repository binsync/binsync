import logging
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

from .control_panel_view import ControlPanelView
from .controller import AngrBinSyncController

from binsync.common.ui import set_ui_version
set_ui_version("PySide2")
from binsync.common.ui.config_dialog import SyncConfig

l = logging.getLogger(__name__)

class BinsyncPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        """
        The entry point for the BinSync plugin. This class is respobsible for both initializing the GUI and
        deiniting it as well. The BinSync plugin also starts the BinsyncController, which is a threaded class
        that pushes and pulls changes every so many seconds.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # init the Sync View on load
        self.controller = AngrBinSyncController(self.workspace)
        self.control_panel_view = ControlPanelView(workspace, 'right', self.controller)

        self.controller.control_panel = self.control_panel_view

        self.sync_menu = None
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        # destroy the sync view on deinit
        self.workspace.remove_view(self.control_panel_view)

    #
    # BinSync GUI Hooks
    #

    MENU_BUTTONS = ('Configure Binsync...', 'Toggle Binsync Panel')
    MENU_CONFIG_ID = 0
    MENU_TOGGLE_PANEL_ID = 1

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog,
            self.MENU_TOGGLE_PANEL_ID: self.toggle_sync_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()


    def open_sync_config_dialog(self):
        if self.workspace.instance.project.am_none:
            # project does not exist yet
            return

        sync_config = SyncConfig(self.controller)
        sync_config.exec_()

        if self.controller.check_client() and self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)

    def toggle_sync_panel(self):
        self.controller.toggle_headless()

        if self.control_panel_view.isVisible():
            self.control_panel_view.close()
            return

        self.workspace.add_view(self.control_panel_view)

    #
    #   BinSync Decompiler Hooks
    #

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str, type_: str, size: int):
        self.controller.make_controller_cmd(self.controller.push_stack_variable,
                                            func.addr, offset, new_name, type_, size)
        return False

    def handle_function_rename(self, func, old_name: str, new_name: str):
        func_addr = func.addr
        self.controller.make_controller_cmd(self.controller.push_function_header,
                                            func_addr, new_name)
        return False

    def handle_comment_changed(self, addr: int, cmt: str, new: bool, decomp: bool):
        self.controller.make_controller_cmd(self.controller.push_comment, addr, cmt, decomp)
        return False
