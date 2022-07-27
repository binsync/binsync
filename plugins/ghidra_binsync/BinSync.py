# Activates the BinSync plugin to allow for configuration and connection
#@category Collaboration
#@menupath Tools.Configure BinSync
#@keybinding ctrl shift b
#@toolbar ghidra_binsync/binsync.png

from SimpleXMLRPCServer import SimpleXMLRPCServer
import os
from threading import Thread
import time
import subprocess
from inspect import getsourcefile
from os.path import abspath

"""
from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder
from ghidra.program.model.address import Address
from ghidra.program.model.lang import LanguageCompilerSpecPair
from ghidra.program.model.listing import Program
from ghidra.util import Msg

from java.lang import IllegalArgumentException
"""

BUSY_LOOP_SLEEPTIME = 0.05


class BSBridgeAPI:
    def __init__(self, server):
        self.server = server

    def shutdown(self):
        self.server.should_work = False

    def ping(self):
        return True

    def bs_connected(self):
        self.server.binsync_connected = True


class BSBridgeServer:
    def __init__(self, ip='localhost', port=9466):
        self.ip = ip
        self.port = port

        self.api = BSBridgeAPI(self)
        self.server_thread = Thread(target=self._worker_thread)
        self.server = None

        self.binsync_connected = False
        self.should_work = False

    def _worker_thread(self):
        self.server = SimpleXMLRPCServer((self.ip, self.port), logRequests=False, allow_none=True)
        self.server.register_introspection_functions()
        self.server.register_multicall_functions()
        self.server.register_instance(self.api)

        while self.should_work:
            self.server.handle_request()

    def start(self):
        self.should_work = True
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.should_work = False
        self.server_thread.join()
        self.server = None

    def wait_for_shutdown(self):
        while True:
            time.sleep(BUSY_LOOP_SLEEPTIME)
            if not self.should_work:
                return

    def wait_for_bs_connection(self, timeout=60*5):
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(BUSY_LOOP_SLEEPTIME)
            if self.binsync_connected:
                return True

        return False


class BinSyncUI:
    ENTRY_SCRIPT_NAME = "binsync_ui.py"

    def __init__(self):
        self.running_path = abspath(getsourcefile(lambda:0))
        self.bs_entry_path = self._get_bs_entry_script_path()

        self.ui_proc = None
        
    def _get_bs_entry_script_path(self):
        dirname = os.path.dirname(self.running_path)
        return os.path.join(dirname, self.ENTRY_SCRIPT_NAME)

    def start(self):
        python_version = "python3"
        python_flags = []

        self.ui_proc = subprocess.Popen([python_version] + python_flags + [self.bs_entry_path])

    def kill(self):
        if self.ui_proc.poll() is None:
            self.ui_proc.kill()

    def is_alive(self):
        if self.ui_proc.poll() is None:
            return True

        return False


if __name__ == "__main__":
    # 1. start bridge service as a new thread
    # 2. start the config UI from Python3, which opens the control panel without starting it
    # 3. wait, with a timeout, for  python3 ui
    #   - if success msg recieved, let the thread keep running as a daemon
    #   - if failure or timeout
    #
    print(abspath(getsourcefile(lambda:0)))
    
     
    """
    bridge = BSBridgeServer()
    bridge.start()
    binsync_ui = BinSyncUI()
    connection = bridge.wait_for_bs_connection()
    if connection:
        print("Someone has connected with BinSync")
    else:
        print("Timeout before connection")
    """