from collections import defaultdict

from PySide6.QtGui import QImage
from PySide6.QtWidgets import (
    QVBoxLayout
)

from binaryninjaui import (
    UIAction,
    UIActionHandler,
    Menu,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
import binaryninja

from libbs.plugin_installer import PluginInstaller
from binsync.controller import BSController
from binsync.ui.control_panel import ControlPanel
from binsync.ui.config_dialog import ConfigureBSDialog


class BinSyncSidebarWidget(SidebarWidget):
    def __init__(self, bv, bn_plugin, name="BinSync"):
        super().__init__(name)
        self._controller = bn_plugin.controllers[bv]
        self._controller.bv = bv
        self._widget = ControlPanel(self._controller)

        layout = QVBoxLayout()
        layout.addWidget(self._widget)
        self.setLayout(layout)


class BinSyncSidebarWidgetType(SidebarWidgetType):
    def __init__(self, bn_plugin):
        binsync_files = PluginInstaller.find_pkg_files("binsync")
        if not binsync_files or not binsync_files.exists():
            raise FileNotFoundError("Failed to find the BinSync package! Is your install corrupted?")

        bs_img_path = binsync_files / "stub_files" / "binsync_binja_logo.png"
        if not bs_img_path.exists():
            raise FileNotFoundError("Could not find BinSync logo image!")

        self._bs_logo = QImage(str(bs_img_path))
        self.plugin = bn_plugin
        super().__init__(self._bs_logo, "BinSync")

    def createWidget(self, frame, data):
        return BinSyncSidebarWidget(data, self.plugin)


class BinjaPlugin:
    def __init__(self):
        # controller stored by a binary view
        self.controllers = defaultdict(BSController)
        self.sidebar_widget_type = None

        if binaryninja.core_ui_enabled():
            self._init_ui()

    def _init_ui(self):
        # config dialog
        configure_binsync_id = "BinSync: Configure..."
        UIAction.registerAction(configure_binsync_id)
        UIActionHandler.globalActions().bindAction(
            configure_binsync_id, UIAction(self._launch_config)
        )
        Menu.mainMenu("Plugins").addAction(configure_binsync_id, "BinSync")

        # control panel widget
        self.sidebar_widget_type = BinSyncSidebarWidgetType(self)
        Sidebar.addSidebarWidgetType(self.sidebar_widget_type)

    def _init_bv_dependencies(self, bv):
        """
        TODO: Add the start artifact watcher call here
        """
        pass

    def _launch_config(self, bn_context):
        bv = bn_context.binaryView
        controller_bv = self.controllers[bv]

        if bv is not None:
            controller_bv.bv = bv

        # exit early if we already configed
        if (controller_bv.bv is not None and controller_bv.check_client()) or bv is None:
            return

        # configure
        dialog = ConfigureBSDialog(controller_bv)
        dialog.exec_()

        # if the config was successful init a full client
        if controller_bv.check_client():
            self._init_bv_dependencies(bv)
