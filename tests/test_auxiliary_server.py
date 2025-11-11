import sys

from binsync.extras.server.server import Server
from binsync.ui.panel_tabs.util_panel import ServerClient
import unittest
import threading
import time

from libbs.artifacts import Artifact, Context

class Context:
    def __init__(self):
        self.addr = 0x400010
        self.func_addr = 0x400000

class Deci:
    def __init__(self):
        self.artifact_change_callbacks:dict[Artifact, list[function]] = {Context:[]}
        self._context = Context()
        
    def gui_active_context(self):
        return self._context
    
    def _update_context(self,new_values:dict[str,int]):
        self._context.addr = new_values["address"]
        self._context.func_addr = new_values["function_address"]
        for callback_fn in self.artifact_change_callbacks[Context]:
            callback_fn(self._context)
        
class Client:
    def __init__(self,username):
        self.master_user = username

class BabyController:
    """
    A minimal implementation of a BSController that contains the information necessary for a ServerClient.
    This avoids the issue of having to create the DecompilerInterface that BSControllers typically need.
    """
    def __init__(self, username):
        self.deci = Deci()
        self.client = Client(username)

class TestAuxServer(unittest.TestCase):
    HOST = "::"
    PORT = 7962
    
    def test_server_no_crash(self):
        """
        Make sure that the server can start up without issues.
        """
        def server_task(server:Server,crash_signal:threading.Event):
            try:
                server.run()
            except:
                crash_signal.set()
        server = Server(self.HOST,self.PORT)
        crash_signal = threading.Event()
        # Make server thread as a daemon
        server_thread = threading.Thread(target=server_task,args=(server,crash_signal))
        server_thread.daemon = True
        server_thread.start()
        server_thread.join(1)
        self.assertFalse(crash_signal.is_set())
        
    def test_run_server(self):
        def server_task(server:Server):
            server.run()
        server = Server(self.HOST,self.PORT)
        # Make server thread as a daemon
        server_thread = threading.Thread(target=server_task,args=(server,))
        server_thread.daemon = True
        server_thread.start()
        time.sleep(1)
        self.assertEqual(server.store._user_map,{})
        




if __name__ == "__main__":
    unittest.main(argv=sys.argv)
