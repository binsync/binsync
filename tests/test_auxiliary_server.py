import sys

from binsync.extras.aux_server.aux_server import Server
from binsync.extras.aux_server.store import ServerStore

from binsync.ui.aux_server_panel.aux_server_window import ClientWorker
from libbs.ui.qt_objects import (
    QThread,
    QWidget,
    Signal,
    QApplication,
    Slot
)
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

class MockUser(QWidget):
    '''
    Handles ownership of ClientWorkers and their threads, as well as related signals
    '''
    connect_signal = Signal(tuple)
    stop_signal = Signal()
    def __init__(self, controller):
        super().__init__()
        self.beliefs = {}
        
        self.worker = ClientWorker(controller)
        self.thread = QThread()
        
        self.worker.moveToThread(self.thread)
        
        self.worker.context_change.connect(self._update_beliefs)
        
        self.connect_signal.connect(self.worker.connect_client)
        self.stop_signal.connect(self.worker.stop)
        
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
    
    def shutdown(self):
        self.stop_signal.emit()
        self.thread.quit()
        self.thread.wait()

    @Slot(dict)
    def _update_beliefs(self, new_beliefs):
        self.beliefs = new_beliefs
        

class TestAuxServer(unittest.TestCase):
    HOST = "127.0.0.1"
    PORT = 7962
        
    def setUp(self):
        self.users:list[MockUser] = []
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication([])
        
    def tearDown(self):
        # Note: Not all clients may be present in self.clients as some tests shut down the clients early
        for user in self.users:
            user.shutdown()
        try:
            self.app
        except:
            pass
        else:
            self.app.quit() # type: ignore # My linter complains that app can be None here
            
    
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
            
        server = Server(self.HOST,self.PORT)
        with ServerThreadManager(server):
            self.users.append(MockUser(MockController("Alice")))
            
            self.users[0].connect_signal.emit((self.HOST, self.PORT))
            time.sleep(1)
            assert server.store._user_count == 1 # Verify that the server received the connection
            self.users[0].stop_signal.emit()
            time.sleep(1)
            assert server.store._user_count == 0 # Verify that server received disconnection
    
    def test_many_connections(self):
        """
        Verify server can handle multiple connections at once
        """
        num_connections = 10
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
                self.users.append(MockUser(controller))
            
            # Start up client threads
            for user in self.users:
                user.connect_signal.emit((self.HOST, self.PORT))
            time.sleep(2)
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
        server = Server(self.HOST,self.PORT)
        with ServerThreadManager(server):
            controller = MockController("Alice")
            self.users.append(MockUser(controller))
            for user in self.users:
                user.connect_signal.emit((self.HOST, self.PORT))
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
        server = Server(self.HOST,self.PORT)
        
        with ServerThreadManager(server):
            # Set up contexts
            controllers:list[MockController] = []
            for i in range(num_connections):
                controller = MockController(f"User_{i}")
                controller.deci._update_context({
                    "address":0x40000+10*i,
                    "function_address":0x500000+10*i
                })
                controllers.append(controller)
                self.users.append(MockUser(controller))
            
            for user in self.users:
                user.connect_signal.emit((self.HOST, self.PORT))
            time.sleep(2)
            
            self.app.processEvents() # required for beliefs to update in this test
            
            # Make sure beliefs have been updated to something
            assert self.users[0].beliefs != {}
            # Make sure everyone's beliefs are the same
            for i in range(len(self.users)-1):
                assert self.users[i].beliefs == self.users[i+1].beliefs
            # Make sure everyone's beliefs match up with the server
            assert self.users[0].beliefs == server.store._user_map  
    
    # def test_link_unlink_projects(self):
    #     '''
    #     Test: Client creates a new group, links a project to that group, then deletes the group. 
    #     There should be errors when deleting the group a second time and when trying to unlink the project (as it is already deleted).
    #     '''
            
    #     server = Server(self.HOST,self.PORT)
    #     project_url = "https://github.com/binsync/binsync.git"
    #     group_name = "binsync"
    #     with ServerThreadManager(server):
    #         self.users.append(MockUser(MockController("Alice")))
    #         for user in self.users:
    #             user.connect_signal.emit((self.HOST, self.PORT))
    #         time.sleep(1)
            
            
    #         # Client makes new group
    #         group_create_result = client.create_group(group_name)
    #         assert group_create_result == (True, "")
            
    #         # Client links a project
    #         link_result = client.link_project(project_url, group_name)
    #         assert link_result == (True, "")
            
    #         # Validate projects list contains only our one project
    #         project_list = client.list_projects()
    #         assert project_list == {
    #             ServerStore.DEFAULT_GROUPNAME: {},
    #             group_name: {
    #                 project_url: None
    #             }
    #         }
        
    #         # Client deletes the group
    #         group_delete_result_1 = client.delete_group(group_name)
    #         assert group_delete_result_1 == (True, "")
            
    #         # Client deletes the group (should error)
    #         group_delete_result_2 = client.delete_group(group_name)
    #         assert group_delete_result_2[0] == False
            
    #         # Client unlinks the project (should error)
    #         unlink_result = client.unlink_project(project_url)
    #         assert unlink_result[0] == False
            
    #         # Validate projects list is empty
    #         project_list = client.list_projects()
    #         assert project_list == {
    #             ServerStore.DEFAULT_GROUPNAME: {}
    #         }
    
    # def test_multi_user_link_unlink_projects(self):
    #     '''
    #     Client A links a project, then Client B lists out linked projects.
    #     Client C then unlinks the project and Client B lists out linked projects again.
    #     '''
    #     def client_task(client:ServerClient):
    #         client.run()
            
    #     server = Server(self.HOST,self.PORT)
    #     with ServerThreadManager(server):
    #         client_a = ServerClient(self.HOST, self.PORT, MockController("Alice"), lambda *args:None)
    #         self.clients.append(client_a)
    #         client_b = ServerClient(self.HOST, self.PORT, MockController("Bob"), lambda *args:None)
    #         self.clients.append(client_b)
    #         client_c = ServerClient(self.HOST, self.PORT, MockController("Carol"), lambda *args:None)
    #         self.clients.append(client_c)
            
    #         for client in self.clients:
    #             self.client_threads.append(threading.Thread(target=client_task,args=(client,)))

    #         for client_thread in self.client_threads:
    #             client_thread.start()
            
    #         project_url = "https://github.com/binsync/binsync.git"
            
    #         # Client A links project
    #         link_result = client_a.link_project(project_url)
    #         assert link_result == (True, "")
            
    #         # Client B lists out projects
    #         list_result_1 = client_b.list_projects()
    #         assert list_result_1 == {
    #             ServerStore.DEFAULT_GROUPNAME: {
    #                 project_url: None
    #             }
    #         }
            
    #         # Client C unlinks project
    #         unlink_result = client_c.unlink_project(project_url)
    #         assert unlink_result == (True, "")
            
    #         # Client B lists out projects
    #         list_result_2 = client_b.list_projects()
    #         assert list_result_2 == {
    #             ServerStore.DEFAULT_GROUPNAME: {}
    #         }
            
if __name__ == "__main__":
    unittest.main(argv=sys.argv)
