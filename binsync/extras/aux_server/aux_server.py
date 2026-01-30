from flask import Flask, request, jsonify, Response
from threading import Lock
import logging
from binsync.extras.aux_server.store import ServerStore
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
        self.app.add_url_rule("/status", view_func=self.return_user_data, methods=["GET"])
        
        self.app.add_url_rule("/link_project", view_func=self.handle_link_project, methods=["POST"])
        self.app.add_url_rule("/unlink_project", view_func=self.handle_unlink_project, methods=["POST"])
        self.app.add_url_rule("/list_projects", view_func=self.return_linked_projects, methods=["GET"])
    
    def handle_connection(self):
        self.store.incrementUser()
        return 'You are connected!'

    def handle_disconnection(self):
        self.store.decrementUser()
        return 'You have disconnected!'

    def receive_function(self):
        if "username" in request.form: # Can't keep track of users if they are not associated with a username
            username = request.form["username"]
            user_info:dict[str,None|int] = {
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
    
    def return_user_data(self):
        '''
        Returns all the user data being tracked by the server.
        
        If an If-None-Match header is provided and the ETag value matches the modification counter, 
        returns a 304 to indicate unchanged data.
        
        '''
        if "If-None-Match" in request.headers: # Check for the presence of an ETag
            etag = request.headers['If-None-Match']
            if not (etag.startswith('"') and etag.endswith('"')):
                return Response("Bad ETag",400)
            user_data = self.store.getUserDataCountNotMatch(int(etag[1:-1]))
            if user_data == None: # User data unchanged
                return Response(status=304)
        else:
            user_data = self.store.getUserData()
        resp = jsonify(user_data[0])
        resp.set_etag(str(user_data[1]))
        return resp
        
    def handle_link_project(self):
        '''
        Links a project into the server based on Git url (with optional Group specifier)
        
        Expected form parameters: url (mandatory) and group (optional, assumed to be None)
        '''
        if "url" in request.form:
            url = request.form["url"]
            if "group" in request.form:
                success = self.store.link_project(url, request.form["group"])
            else:
                success = self.store.link_project(url)
            if success:
                return Response("OK", 200)
            else:
                return Response("Unknown Error", 500)
        else:
            return Response("Missing Project URL", 400)
    
    def handle_unlink_project(self):
        if "url" in request.form:
            url = request.form["url"]
            if "group" in request.form:
                status = self.store.unlink_project(url, request.form["group"])
            else:
                status = self.store.unlink_project(url)
            if status[0]:
                return Response("OK", 200)
            else:
                return Response(status[1], 500)
        else:
            return Response("Missing Project URL", 400)
    
    def return_linked_projects(self):
        '''
        Returns all linked projects.
        '''
        return jsonify(self.store.list_projects())
    
    def run(self):
        self.app.run(self.host,self.port)

    