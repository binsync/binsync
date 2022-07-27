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
from ghidra.program.model.symbol import SourceType

BUSY_LOOP_SLEEPTIME = 0.05


class BSBridgeAPI:
    def __init__(self, server):
        self.server = server

    def shutdown(self):
        self.server.should_work = False
        del self.server.server

    def ping(self):
        return True

    def set_controller_status(self, status):
        self.server.binsync_ready = status

    #
    # decompiler private api
    #

    def _find_ProgramPlugin(self, tool):
        """ Use the provided tool (probably something like CodeBrowser) to find any loaded plugin that extends ProgramPlugin,
            which gives access to useful state like the current address, etc
        """
        plugins = tool.getManagedPlugins()
        plugin = None
        for i in range(0, plugins.size()):
            plugin = plugins.get(i)
            if "getProgramLocation" in dir(plugin):
                # it's a program plugin! that'll work just fine
                return plugin

    def _get_real_current_addr(self):
        tool = getState().getTool()
        prog_plugin = self._find_ProgramPlugin(tool)
        loc = prog_plugin.getProgramLocation()
        return loc.address

    def _get_real_current_program(self):
        tool = getState().getTool()
        prog_plugin = self._find_ProgramPlugin(tool)
        return prog_plugin.getCurrentProgram()

    def _make_addr(self, addr):
        address = currentProgram.getAddressFactory().getAddress(hex(addr))
        return address

    def _get_function(self, addr):
        addr = self._make_addr(addr + 0x100000)
        curr_prog = self._get_real_current_program()
        fm = curr_prog.getFunctionManager()
        func = fm.getFunctionAt(addr)
        return func

    def _get_nearest_function(self, addr):
        fm = currentProgram.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        return func


    #
    # decompiler api
    #

    def context(self):
        addr = self._get_real_current_addr()
        func = self._get_nearest_function(addr)

        if func is None:
            return {}

        size = int(func.getBody().getNumAddresses())
        name = str(func.getName())
        func_addr = int(func.entryPoint.toString(), 16)

        return {
            "name": name,
            "size": size,
            "func_addr": func_addr - 0x100000
        }

    def get_func_size(self, addr):
        func = self._get_function(addr)
        return int(func.getBody().getNumAddresses()) 

    def set_func_name(self, addr, name):
        func = self._get_function(addr)
        if func is None:
            return

        func.setName(str(name), SourceType.USER_DEFINED)

    def get_func_name(self, addr):
        func = self._get_function(addr)
        return str(func.getName())


class BSBridgeServer:
    def __init__(self, host='localhost', port=9466):
        self.host = host
        self.port = port

        self.api = BSBridgeAPI(self)
        self.server_thread = Thread(target=self._worker_thread)
        self.server = None

        self.binsync_ready = None
        self.should_work = False

    def _worker_thread(self):
        self.server = SimpleXMLRPCServer((self.host, self.port), logRequests=False, allow_none=True)
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
        self.wait_for_shutdown()
        self.server = None

    def wait_for_shutdown(self):
        while True:
            time.sleep(BUSY_LOOP_SLEEPTIME)
            if not self.should_work:
                try:
                    self.server.ping()
                except Exception:
                    break

    def wait_for_bs_connection(self, timeout=60*5):
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(BUSY_LOOP_SLEEPTIME)
            if self.binsync_ready is not None:
                break

        return self.binsync_ready


class BinSyncUI:
    ENTRY_SCRIPT_NAME = "binsync_ui.py"

    def __init__(self):
        self.running_path = abspath(getsourcefile(lambda:0))
        self.bs_entry_path = self._get_bs_entry_script_path()

        self.ui_proc = None
    #
    # public api
    #

    def start(self):
        python_version = "python3"
        python_flags = []

        self.ui_proc = subprocess.Popen([python_version] + python_flags + [self.bs_entry_path])

    def stop(self):
        if self.ui_proc.poll() is None:
            self.ui_proc.kill()

    def is_alive(self):
        if self.ui_proc.poll() is None:
            return True

        return False

    def _get_bs_entry_script_path(self):
        #dirname = os.path.dirname(self.running_path)
        dirname = os.path.join(os.getenv("HOME"), "ghidra_scripts")
        return os.path.join(dirname, self.ENTRY_SCRIPT_NAME)


if __name__ == "__main__":
    # 1. start bridge service as a new thread
    # 2. start the config UI from Python3, which opens the control panel without starting it
    # 3. wait, with a timeout, for  python3 ui
    #   - if success msg recieved, let the thread keep running as a daemon
    #   - if failure or timeout
    print("[+] Starting configuration...")
    bridge = BSBridgeServer()
    bridge.start()
    print("[+] Starting UI...")
    binsync_ui = BinSyncUI()
    binsync_ui.start()
    print("[+] Waiting for connection...")
    print("Process is", binsync_ui.is_alive())
    connection = bridge.wait_for_bs_connection()
    if connection:
        print("[+] BinSync Configuration was Successful!")
        bridge.wait_for_shutdown()
    else:
        print("[-] BinSync Configuration failed")
        bridge.stop()

