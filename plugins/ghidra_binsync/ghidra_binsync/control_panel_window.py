import logging

from binsync.common.ui.qt_objects import QVBoxLayout, QMainWindow, QApplication
from binsync.common.ui.control_panel import ControlPanel
from binsync.common.ui.config_dialog import SyncConfig

from .controller import GhidraBinSyncController


l = logging.getLogger(__name__)


class ControlPanelWindow(QMainWindow):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self):
        super(ControlPanelWindow, self).__init__()
        self.setWindowTitle("BinSync")
        self.width_hint = 300

        self.controller: GhidraBinSyncController = GhidraBinSyncController()
        self.control_panel = ControlPanel(self.controller)

        self._init_widgets()

    #
    # Private methods
    #

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)

    #
    # handlers
    #

    def configure(self):
        config = SyncConfig(self.controller)
        config.show()
        config.exec_()
        client_connected = self.controller.check_client()

        # setup bridge and alert it we are configuring
        bridge_connected = self.controller.connect_ghidra_bridge()
        if bridge_connected:
            self.controller.bridge.set_controller_status(client_connected)

        return client_connected and bridge_connected

    def closeEvent(self, event):
        self.controller.bridge.server.stop()


def start_ui():
    app = QApplication()
    cp_window = ControlPanelWindow()

    # control panel should stay hidden until a good config happens
    cp_window.hide()
    connected = cp_window.configure()
    if connected:
        cp_window.show()
    else:
        exit(1)

    app.exec_()
