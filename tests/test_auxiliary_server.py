import sys

from binsync.extras.aux_server.aux_server import Server
from binsync.extras.aux_server.aux_client import ServerClient
import unittest
import threading
import time
import socket
from werkzeug.serving import make_server
from contextlib import contextmanager
from libbs.artifacts import Artifact, Context

class MockContext:
    def __init__(self):
        self.addr = 0x400010
        self.func_addr = 0x400000

class MockDeci:
    def __init__(self):
        self.artifact_change_callbacks:dict[Artifact, list[function]] = {Context:[]}
        self._context = MockContext()
        
    def gui_active_context(self):
        return self._context
    
    def _update_context(self,new_values:dict[str,int]):
        self._context.addr = new_values["address"]
        self._context.func_addr = new_values["function_address"]
        for callback_fn in self.artifact_change_callbacks[Context]:
            callback_fn(self._context)
        
class MockClient:
    def __init__(self,username):
        self.master_user = username

class MockController:
    """
    A minimal implementation of a BSController that contains the information necessary for a ServerClient.
    This avoids the issue of having to create the DecompilerInterface that BSControllers typically need.
    """
    def __init__(self, username):
        self.deci = MockDeci()
        self.client = MockClient(username)
        
class ServerThreadManager():
    """
    Implementation of the server that enables shutting down the server in between tests
    """
    def __init__(self, server:Server):
        self.server = make_server(server.host,server.port,server.app)
        
    def __enter__(self):
        self._thread = threading.Thread(target=self.server.serve_forever)
        self._thread.start()
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.shutdown()
        self._thread.join()
        

class TestAuxServer(unittest.TestCase):
    HOST = "127.0.0.1"
    PORT = 7962
        
    def setUp(self):
        self.clients:list[ServerClient] = []
        self.client_threads:list[threading.Thread] = []
        
    def tearDown(self):
        # Note: Not all clients may be present in self.clients as some tests shut down the clients early
        for client in self.clients:
            client.stop()
        for client_thread in self.client_threads:
            client_thread.join()
            
    
    def test_run_server(self):
        """
        Make sure that the server can start up without issues.
        """
        server = Server(self.HOST,self.PORT)
        with ServerThreadManager(server):
            time.sleep(1)
        assert server.store._user_map == {} # Validate that the initial map of user functions is empty
        assert server.store._user_count == 0 # Validate that the initial user count is 0
        
    def test_single_connection(self):
        """
        Make sure a single user can connect and disconnect with no issues
        """
        def client_task(client:ServerClient):
            client.run()
            
        server = Server(self.HOST,self.PORT)
        self.clients.append(ServerClient(self.HOST, self.PORT, MockController("Alice"),lambda *args: None))
        with ServerThreadManager(server):
            self.client_threads.append(threading.Thread(target=client_task,args=(self.clients[0],)))
            for client_thread in self.client_threads:
                client_thread.start()
            time.sleep(1)
            
            assert server.store._user_count == 1 # Verify that the server received the connection
            self.clients.pop(0).stop()
            time.sleep(1)
            assert server.store._user_count == 0 # Verify that server received disconnection
    
    def test_many_connections(self):
        """
        Verify server can handle multiple connections at once
        """
        num_connections = 10
        def client_task(client:ServerClient):
            client.run()
        server = Server(self.HOST,self.PORT)
        controllers:list[MockController] = []
        with ServerThreadManager(server):
            # Set up contexts
            for i in range(num_connections):
                controller = MockController(f"User_{i}")
                controller.deci._update_context({
                    "address":0x40000+10*i,
                    "function_address":0x500000+10*i
                })
                controllers.append(controller)
                client = ServerClient(self.HOST, self.PORT, controller,lambda *args:None)
                self.clients.append(client)
                client_thread = threading.Thread(target=client_task,args=(client,))
                self.client_threads.append(client_thread)
            
            # Start up client threads
            for client_thread in self.client_threads:
                client_thread.start()
            time.sleep(1)
            # Make sure that each user's function context is present in the server's storage
            contexts_dict,_ = server.store.getUserData()
            for controller in controllers:
                user_entry = contexts_dict[controller.client.master_user]
                assert user_entry["addr"] == controller.deci._context.addr
                assert user_entry["func_addr"] == controller.deci._context.func_addr
    
    def test_context_change(self):
        """
        Verify that clients contact the server when their context changes
        """
        def client_task(client:ServerClient):
            client.run()
            
        server = Server(self.HOST,self.PORT)
        with ServerThreadManager(server):
            controller = MockController("Alice")
            self.clients.append(ServerClient(self.HOST, self.PORT, controller,lambda *args: None))
            self.client_threads.append(threading.Thread(target=client_task,args=(self.clients[0],)))
            for client_thread in self.client_threads:
                client_thread.start()
            time.sleep(1)
            
            contexts_dict,_ = server.store.getUserData()
            user_entry = contexts_dict[controller.client.master_user]
            assert user_entry["addr"] == controller.deci._context.addr
            assert user_entry["func_addr"] == controller.deci._context.func_addr
            
            # Update!
            controller.deci._update_context({
                "address":0x444444,
                "function_address":0x454545
            })
            time.sleep(1)
            
            contexts_dict,_ = server.store.getUserData()
            user_entry = contexts_dict[controller.client.master_user]
            assert user_entry["addr"] == controller.deci._context.addr
            assert user_entry["func_addr"] == controller.deci._context.func_addr
                
    def test_see_other_clients(self):
        num_connections = 10
        def client_task(client:ServerClient):
            client.run()
        server = Server(self.HOST,self.PORT)
        controllers:list[MockController] = []
        client_beliefs = []
        
        def update_belief(index, context):
            client_beliefs[index] = context
            
        def make_belief_lambda(index):
            # We need this function because of lambda late binding
            return lambda context:update_belief(index,context)
        with ServerThreadManager(server):
            # Set up contexts
            for i in range(num_connections):
                controller = MockController(f"User_{i}")
                controller.deci._update_context({
                    "address":0x40000+10*i,
                    "function_address":0x500000+10*i
                })
                controllers.append(controller)
                client = ServerClient(self.HOST, self.PORT, controller,make_belief_lambda(i))
                self.clients.append(client)
                client_thread = threading.Thread(target=client_task,args=(client,))
                self.client_threads.append(client_thread)
                
                client_beliefs.append({})
            # Start up client threads
            for client_thread in self.client_threads:
                client_thread.start()
            time.sleep(2)
            
            # Make sure beliefs have been updated to something
            assert client_beliefs[0] != {}
            # Make sure everyone's beliefs are the same
            for i in range(len(client_beliefs)-1):
                assert client_beliefs[i] == client_beliefs[i+1]
            # Make sure everyone's beliefs match up with the server
            assert client_beliefs[0] == server.store._user_map  
        


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
