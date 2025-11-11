import sys

from binsync.extras.server.server import Server
from binsync.ui.panel_tabs.util_panel import ServerClient
import unittest
import threading
import time
import socket
from werkzeug.serving import make_server

from libbs.artifacts import Artifact, Context

class BabyContext:
    def __init__(self):
        self.addr = 0x400010
        self.func_addr = 0x400000

class BabyDeci:
    def __init__(self):
        self.artifact_change_callbacks:dict[Artifact, list[function]] = {Context:[]}
        self._context = BabyContext()
        
    def gui_active_context(self):
        return self._context
    
    def _update_context(self,new_values:dict[str,int]):
        self._context.addr = new_values["address"]
        self._context.func_addr = new_values["function_address"]
        for callback_fn in self.artifact_change_callbacks[BabyContext]:
            callback_fn(self._context)
        
class BabyClient:
    def __init__(self,username):
        self.master_user = username

class BabyController:
    """
    A minimal implementation of a BSController that contains the information necessary for a ServerClient.
    This avoids the issue of having to create the DecompilerInterface that BSControllers typically need.
    """
    def __init__(self, username):
        self.deci = BabyDeci()
        self.client = BabyClient(username)

class ServerThread(threading.Thread):
    """
    Implementation of the server that enables shutting down the server in between tests
    """
    def __init__(self, server:Server):
        super().__init__()
        self.server = make_server(server.host,server.port,server.app)
        
    def run(self):
        self.server.serve_forever()
        
    def shutdown(self):
        self.server.shutdown()

class TestAuxServer(unittest.TestCase):
    HOST = "::"
    PORT = 7962
    MAX_TRIES = 20
 
    def test_server_no_crash(self):
        """
        Make sure that the server can start up without issues.
        """
        server = Server(self.HOST,self.PORT)
        crash_signal = threading.Event()
        server_thread = ServerThread(server)
        server_thread.start()
        time.sleep(1)
        server_thread.shutdown()
        server_thread.join()
        
    def test_run_server(self):
        server = Server(self.HOST,self.PORT)
        server_thread = ServerThread(server)
        server_thread.start()
        time.sleep(1)
        server_thread.shutdown()
        self.assertEqual(server.store._user_map,{})
        server_thread.join()
        

    
    


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
