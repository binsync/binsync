from flask import Flask, request
from threading import Lock
import logging
from binsync.extras.server.store import ServerStore
l = logging.getLogger(__name__)
    
class Server:
    def __init__(self,host,port,store:ServerStore):
        self.host = host
        self.port = port
        self.store = store
        self.app = self._create_app()
    
    def _create_app(self):
        app = Flask(__name__)
        store = self.store
        @app.route('/connect')
        def handle_connection():
            store.incrementUser()
            return 'You are connected!'

        @app.route("/disconnect")
        def handle_disconnection():
            store.decrementUser()
            return 'You have disconnected!'

        @app.route("/function",methods=["POST"])
        def receive_function():
            if "username" in request.form: # Can't keep track of users if they are not associated with a username
                username = request.form["username"]
                user_info = {
                    "addr":None,
                    "func_addr":None
                }
                if "address" in request.form:
                    user_info["addr"] = int(request.form["address"])
                if "function_address" in request.form:
                    user_info["func_addr"] = int(request.form["function_address"])
                store.setUserData(username,user_info)
            l.info(store.getUserData())
            return "OK"
        
        return app

    def run(self):
        self.app.run(self.host,self.port)

    