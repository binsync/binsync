import logging
import sys
import threading
from time import sleep
import subprocess

from libbs.ui.version import set_ui_version
set_ui_version("PySide6")
from libbs.ui.qt_objects import QMainWindow, QApplication, QTimer
from libbs.api import DecompilerInterface
from libbs.api.decompiler_server import DecompilerServer

from binsync.ui.control_panel import ControlPanel
from binsync.ui.config_dialog import ConfigureBSDialog
from binsync.controller import BSController

_l = logging.getLogger(__name__)


class ControlPanelWindow(QMainWindow):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, deci=None):
        super(ControlPanelWindow, self).__init__()
        self.setWindowTitle("BinSync")
        self.width_hint = 300

        self._interface = deci or DecompilerInterface.discover()
        self.controller = BSController(decompiler_interface=self._interface)
        self.control_panel = ControlPanel(self.controller)
        self._init_widgets()

    def _init_widgets(self):
        self.control_panel.show()
        self.setCentralWidget(self.control_panel)

    #
    # handlers
    #

    def configure(self):
        config = ConfigureBSDialog(self.controller)
        config.show()
        config.exec_()
        return self.controller.check_client()

    def closeEvent(self, event):
        self.controller.shutdown()
        # Brief delay to allow threads to finish cleanup
        # With the Scheduler timeout fix, threads should exit quickly
        QTimer.singleShot(200, QApplication.quit)


def start_ghidra_ui():
    from libbs.api.decompiler_client import DecompilerClient
    deci = DecompilerClient.discover()
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    # Prevent the application from quitting when the last window is closed
    app.setQuitOnLastWindowClosed(False)
    cp_window = ControlPanelWindow(deci=deci)

    # control panel should stay hidden until a good config happens
    cp_window.hide()
    connected = cp_window.configure()
    if connected:
        cp_window.show()
    else:
        sys.exit(1)
    app.exec()

class GhidraRemoteInterfaceWrapper:
    """
    This class is a wrapper class to start the Ghidra Interface with a server so that the GUI can connect in
    another process.
    """

    def __init__(self, *args, **kwargs):
        #import remote_pdb; remote_pdb.RemotePdb('localhost', 4444).set_trace()
        self.server = DecompilerServer(force_decompiler="ghidra")
        #self.server.start()
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.run()
        sleep(1)
        _l.info("Server started on socket: %s", self.server.socket_path)
        self.start_gui_in_new_process()

    @staticmethod
    def start_gui_in_new_process():
        _l.info("Starting the Ghidra BinSync UI in a new process...")
        # first attempt to use the binsync binary
        proc = subprocess.Popen(
            ["binsync", "-s", "ghidra"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        sleep(1)
        if proc.poll() is not None:
            _l.warning("Unable to start the Ghidra BinSync UI using the 'binsync' binary: %s", proc.stderr.read())
            # fallback to starting the UI using python modules
            proc = subprocess.Popen(
                ["python", "-m", "binsync", "-s", "ghidra"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            sleep(1)
            if proc.poll() is not None:
                raise RuntimeError(f"Unable to start the new Python process for the Ghidra BinSync UI: {proc.stderr.read()}")
        _l.info("Ghidra BinSync UI process started with PID %d", proc.pid)

    @property
    def gui_plugin(self):
        """
        Just a stub to conform to the interface expected by the decompiler.
        """
        return None