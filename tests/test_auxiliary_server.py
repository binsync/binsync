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
        for callback_fn in self.artifact_change_callbacks[Context]:
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
    # These cannot be changed for now because the client can only connect to localhost on port 7962
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
        self.assertEqual(server.store._user_map,{}) # Validate that the initial map of user functions is empty
        self.assertEqual(server.store._user_count,0) # Validate that the initial user count is 0
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
        try:
            client_threads:list[threading.Thread] = []
            client_threads.append(threading.Thread(target=client_task,args=(client,)))
            for client_thread in client_threads:
                client_thread.start()
            time.sleep(1)
            
            self.assertEqual(server.store._user_count,1) # Verify that the server received the connection
            
            client.stop()
            time.sleep(1)
            self.assertEqual(server.store._user_count,0) # Verify that server received disconnection
            
            for client_thread in client_threads:
                client_thread.join()
        finally:
            server_thread.shutdown()
            server_thread.join()
    
    def test_many_connections(self):
        """
        Verify server can handle multiple connections at once
        """
        num_connections = 10
        def client_task(client:ServerClient):
            client.run()
        server = Server(self.HOST,self.PORT)
        server_thread = ServerThread(server)
        server_thread.start()
        try:
            controllers:list[BabyController] = []
            clients:list[ServerClient] = []
            client_threads:list[threading.Thread] = []
            try:
                # Set up contexts
                for i in range(num_connections):
                    controller = BabyController(f"User_{i}")
                    controller.deci._update_context({
                        "address":0x40000+10*i,
                        "function_address":0x500000+10*i
                    })
                    controllers.append(controller)
                    client = ServerClient(controller,lambda *args:None)
                    clients.append(client)
                    client_thread = threading.Thread(target=client_task,args=(client,))
                    client_threads.append(client_thread)
                
                # Start up client threads
                for client_thread in client_threads:
                    client_thread.start()
                time.sleep(1)
                # Make sure that each user's function context is present in the server's storage
                contexts_dict,_ = server.store.getUserData()
                for controller in controllers:
                    user_entry = contexts_dict[controller.client.master_user]
                    self.assertTrue(user_entry["addr"] == controller.deci._context.addr)
                    self.assertTrue(user_entry["func_addr"] == controller.deci._context.func_addr)
            finally:
                for client in clients:
                    client.stop()
                for client_thread in client_threads:
                    client_thread.join()
        finally:
            server_thread.shutdown()
            server_thread.join()
        
        


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
