from collections import defaultdict
from pathlib import Path
import pkg_resources

from PySide6.QtGui import QImage
from PySide6.QtWidgets import (
    QDockWidget,
    QWidget,
    QApplication,
    QMenu,
    QMainWindow,
    QMenuBar,
    QVBoxLayout
)

from binaryninjaui import DockContextHandler
from binaryninjaui import (
    UIAction,
    UIActionHandler,
    Menu,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
import binaryninja

from binsync.controller import BSController
from binsync.ui.control_panel import ControlPanel
from binsync.ui.config_dialog import ConfigureBSDialog


def find_main_window():
    main_window = None
    for x in QApplication.allWidgets():
        if not isinstance(x, QDockWidget):
            continue
        main_window = x.parent()
        if isinstance(main_window, (QMainWindow, QWidget)):
            break
        else:
            main_window = None

    if main_window is None:
        # oops cannot find the main window
        raise Exception("Main window is not found.")
    return main_window


dockwidgets = [ ]

class BinjaWidgetBase:
    def __init__(self):
        self._main_window = None
        self._menu_bar = None
        self._plugin_menu = None

    @property
    def main_window(self):
        if self._main_window is None:
            self._main_window = find_main_window()
        return self._main_window

    @property
    def menu_bar(self):
        if self._menu_bar is None:
            self._menu_bar = next(
                iter(x for x in self._main_window.children() if isinstance(x, QMenuBar))
            )
        return self._menu_bar

    @property
    def plugin_menu(self):
        if self._plugin_menu is None:
            self._plugin_menu = next(
                iter(
                    x
                    for x in self._menu_bar.children()
                    if isinstance(x, QMenu) and x.title() == u"Plugins"
                )
            )
        return self._plugin_menu

    def add_tool_menu_action(self, name, func):
        self.plugin_menu.addAction(name, func)


class BinjaDockWidget(QWidget, DockContextHandler):
    def __init__(self, name, parent=None):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.base = BinjaWidgetBase()

        # self.hide()
        self.show()

    def toggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()


class BinjaWidget(QWidget):
    def __init__(self, tabname):
        super(BinjaWidget, self).__init__()
        # self._core = _instance()
        # self._core.addTabWidget(self, tabname)


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
        bs_img_path = Path(
            pkg_resources.resource_filename("binsync", "interface_overrides/binja/binsync_binja_logo.png")
        ).absolute()
        if not bs_img_path.exists():
            raise FileNotFoundError("Could not find BinSync logo image")

        self._bs_logo = QImage(str(bs_img_path))
        self.plugin = bn_plugin
        super().__init__(self._bs_logo, "BinSync")

    def createWidget(self, frame, data):
        return BinSyncSidebarWidget(data, self.plugin)


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
