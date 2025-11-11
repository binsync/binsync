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
        
    def test_run_server(self):
        """
        Make sure that the server can start up without issues.
        """
        server = Server(self.HOST,self.PORT)
        server_thread = ServerThread(server)
        server_thread.start()
        time.sleep(1)
        server_thread.shutdown()
        self.assertEqual(server.store._user_map,{})
        self.assertEqual(server.store._user_count,0)
        server_thread.join()
        
    def test_single_connection(self):
        """
        Make sure a single user can connect and disconnect with no issues
        """
            
        def client_task(client:ServerClient):
            client.run()
        server = Server(self.HOST,self.PORT)
        client = ServerClient(BabyController("Alice"),lambda *args: None)
        server_thread = ServerThread(server)
        server_thread.start()
        
        client_threads:list[threading.Thread] = []
        client_threads.append(threading.Thread(target=client_task,args=(client,)))
        for client_thread in client_threads:
            client_thread.start()
        time.sleep(1)
        # Verify that the server received the connection
        self.assertEqual(server.store._user_count,1)
        client.stop()
        time.sleep(1)
        self.assertEqual(server.store._user_count,0)
        for client_thread in client_threads:
            client_thread.join()
        server_thread.shutdown()
        server_thread.join()
    
    


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
