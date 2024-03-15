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

from libbs.plugin_installer import PluginInstaller
from libbs.decompilers.binja.interface import BinjaInterface

from binsync.controller import BSController
from binsync.ui.control_panel import ControlPanel
from binsync.ui.config_dialog import ConfigureBSDialog


class BinSyncSidebarWidget(SidebarWidget):
    def __init__(self, bv, bs_interface, name="BinSync"):
        super().__init__(name)
        self._controller = bs_interface.controllers[bv]
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


class BinjaBSInterface(BinjaInterface):
    """
    This is fairly complicated due to the way you make plugins in Binary Ninja. Every plugin is supposed to be aware
    of BV, which it uses to interact with the BN core. This BS Interface it to first create a UI that loads into
    binary ninja regardless of what binary you are interacting with. Then, inside the config launcher a new
    BS Interface is created to watch artifacts for THAT specific BN BV.
    """

    def __init__(self, *args, **kwargs):
        self.controllers = defaultdict(BSController)
        self.sidebar_widget_type = None
        super().__init__(*args, **kwargs)

    def _init_gui_components(self, *args, **kwargs):
        if super()._init_gui_components(*args, **kwargs):
            # config dialog
            configure_binsync_id = "BinSync: Configure..."
            UIAction.registerAction(configure_binsync_id)
            UIActionHandler.globalActions().bindAction(
                configure_binsync_id, UIAction(self._launch_bs_config)
            )
            Menu.mainMenu("Plugins").addAction(configure_binsync_id, "BinSync")

            # control panel widget
            self.sidebar_widget_type = BinSyncSidebarWidgetType(self)
            Sidebar.addSidebarWidgetType(self.sidebar_widget_type)

    def _launch_bs_config(self, bn_context):
        bv = bn_context.binaryView
        bs_controller = self.controllers[bv]

        # exit early if we already configured
        if (bs_controller.deci.bv is not None and bs_controller.check_client()) or bv is None:
            return

        # configure
        self.bv = bv
        bs_controller.deci.bv = bv
        dialog = ConfigureBSDialog(bs_controller)
        dialog.exec_()

        # if the config was successful start the artifact watchers
        if bs_controller.check_client():
            bs_controller.deci.start_artifact_watchers()
