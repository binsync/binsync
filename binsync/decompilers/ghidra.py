import logging
import sys

from libbs.ui.qt_objects import QMainWindow, QApplication
from binsync.ui.control_panel import ControlPanel
from binsync.ui.config_dialog import ConfigureBSDialog

from .controller import GhidraBSController


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

        self.controller: GhidraBSController = GhidraBSController()
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
        # setup bridge and alert it we are configuring
        self.controller.connect_ghidra_bridge()

        config = ConfigureBSDialog(self.controller)
        config.show()
        config.exec_()
        client_connected = self.controller.check_client()

        return True

    def closeEvent(self, event):
        self.controller.ghidra.server.stop()


def start_ui():
    app = QApplication()
    cp_window = ControlPanelWindow()

    # control panel should stay hidden until a good config happens
    cp_window.hide()
    connected = cp_window.configure()
    if connected:
        cp_window.show()
    else:
        sys.exit(1)

    app.exec_()
