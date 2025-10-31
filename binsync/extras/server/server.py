from flask import Flask, request, jsonify, Response
from threading import Lock
import logging
from binsync.extras.server.store import ServerStore
l = logging.getLogger(__name__)
    
class Server:
    def __init__(self,host,port):
        self.host = host
        self.port = port
        self.store = ServerStore()
        self.app = Flask(__name__)
        
        self.app.add_url_rule("/connect", view_func=self.handle_connection, methods=["GET"])
        self.app.add_url_rule("/disconnect", view_func=self.handle_disconnection, methods=["GET"])
        self.app.add_url_rule("/function", view_func=self.receive_function, methods=["POST"])
    
    def handle_connection(self):
        self.store.incrementUser()
        return 'You are connected!'

    def handle_disconnection(self):
        self.store.decrementUser()
        return 'You have disconnected!'

    def receive_function(self):
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
            self.store.setUserData(username,user_info)
        l.info(self.store.getUserData())
        return "OK"
    
        @app.route("/status",methods=["GET"])
        def return_user_data():
            if "If-None-Match" in request.headers:
                etag = request.headers['If-None-Match']
                if not (etag.startswith('"') and etag.endswith('"')):
                    return Response("Bad ETag",400)
                user_data = store.getUserDataCountNotMatch(int(etag[1:-1]))
                if user_data == None: # User data unchanged
                    return Response(status=304)
            else:
                user_data = store.getUserData()
            resp = jsonify(user_data[0])
            resp.set_etag(str(user_data[1]))
            return resp
        
        return app

    def run(self):
        self.app.run(self.host,self.port)

    