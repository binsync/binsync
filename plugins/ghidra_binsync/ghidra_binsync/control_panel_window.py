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

        self.controller: GhidraBinSyncController = GhidraBinSyncController()
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

        self.width_hint = 300

    def configure(self):
        config = SyncConfig(self.controller)
        config.show()
        config.exec_()

        #if self.controller.check_client():
        print("Connected!")

    #
    # Private methods
    #

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)


def start_ui():
    app = QApplication()
    cp_window = ControlPanelWindow()
    cp_window.hide()

    cp_window.configure()
    cp_window.show()

    app.exec_()
