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
