
set_ui_version("PySide6")
from binsync.ui.control_panel import ControlPanel
from libbs.ui.qt_objects import QVBoxLayout

from .controller import AngrBSController
from libbs.decompilers.angr.interface import AngrInterface
from libbs.decompilers.angr.compat import GenericBSAngrManagementPlugin

l = logging.getLogger(__name__)


class ControlPanelView(BaseView):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, instance, default_docking_position, controller, *args, **kwargs):
        super().__init__('sync', instance, instance.workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "BinSync: Control Panel"

        self.controller: AngrBSController = controller
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

        self.width_hint = 300

    def reload(self):
        pass

    #
    # Private methods
    #

    def _init_widgets(self):
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.control_panel)
        self.setLayout(main_layout)

# pylint: disable=wrong-import-position,wrong-import-order
import logging

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace
from libbs.ui.version import set_ui_version

set_ui_version("PySide6")
from binsync.ui.config_dialog import ConfigureBSDialog
from .control_panel_view import ControlPanelView
from .controller import AngrBSController

from libbs.data import (
    StackVariable, FunctionHeader, Comment
)

l = logging.getLogger(__name__)


class BinsyncPlugin(GenericBSAngrManagementPlugin):
    """
    Controller plugin for BinSync
    """
    def __init__(self, workspace: Workspace, interface: AngrInterface):
        """
        The entry point for the BinSync plugin. This class is respobsible for both initializing the GUI and
        deiniting it as well. The BinSync plugin also starts the BinsyncController, which is a threaded class
        that pushes and pulls changes every so many seconds.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace, interface)

        # init the Sync View on load
        self.controller = AngrBSController(workspace=self.workspace)
        self.control_panel_view = ControlPanelView(workspace.main_instance, 'right', self.controller)
        self.controller.control_panel = self.control_panel_view

        self.sync_menu = None
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        self.controller.stop_worker_routines()
        # destroy the sync view on deinit
        self.workspace.remove_view(self.control_panel_view)

    #
    # BinSync GUI Hooks
    #

    MENU_BUTTONS = ('Configure Binsync ...', 'Toggle Binsync Panel')
    MENU_CONFIG_ID = 0
    MENU_TOGGLE_PANEL_ID = 1

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.main_instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog,
            self.MENU_TOGGLE_PANEL_ID: self.toggle_sync_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()


    def open_sync_config_dialog(self):
        if self.workspace.main_instance.project.am_none:
            # project does not exist yet
            return

        sync_config = ConfigureBSDialog(self.controller)
        sync_config.exec_()

        if self.controller.check_client() and self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)

    def toggle_sync_panel(self):
        self.controller.toggle_headless()

        if self.control_panel_view.isVisible():
            self.control_panel_view.close()
            return

        self.workspace.add_view(self.control_panel_view)


class BSAngrInterface(AngrInterface):
    def _init_gui_plugin(self, *args, **kwargs):
        self.gui_plugin = BinsyncPlugin(self.workspace, self)
        self.workspace.plugins.register_active_plugin(self._plugin_name, self.gui_plugin)
        return self.gui_plugin
