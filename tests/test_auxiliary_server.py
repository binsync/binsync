import sys

from binsync.extras.server.server import Server
from binsync.ui.panel_tabs.util_panel import ServerClient
import unittest
import threading
import time
from binsync.controller import BSController

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
