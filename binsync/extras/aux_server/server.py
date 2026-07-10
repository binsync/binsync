import binsync.extras.aux_server as aux_server
from flask import Flask, request, jsonify, Response
import threading
import logging
from binsync.extras.aux_server.store import ServerStore
from werkzeug.serving import make_server
l = logging.getLogger(__name__)
class Server:
    def __init__(self, host, port, inactive_poll_sec=2, inactive_timeout_sec=30):
        """
        @param host: The host address of the server.
        @param port: The host port of the server.
        @param inactive_poll_sec: How frequently the server should check for inactive users. 
        @param inactive_timeout_sec: The threshold at which users will be considered inactive.
        """
        self.host = host
        self.port = port
        self.inactive_poll_sec = inactive_poll_sec
        self.inactive_timeout_sec = inactive_timeout_sec
        self.store = ServerStore()
        self.app = Flask(__name__)
        # When returning the list of linked projects, we want order to be preserved in case users care
        self.app.json.sort_keys = False # type: ignore
        
        self.app.before_request(self.user_heartbeat)

        self.app.add_url_rule("/version", view_func=self.return_version, methods=["GET"])

        self.app.add_url_rule("/connect", view_func=self.handle_connection, methods=["GET"])
        self.app.add_url_rule("/disconnect", view_func=self.handle_disconnection, methods=["GET"])
        self.app.add_url_rule("/function", view_func=self.receive_function, methods=["POST"])
        self.app.add_url_rule("/status", view_func=self.return_user_data, methods=["GET"])
        
        self.app.add_url_rule("/create_group", view_func=self.handle_create_group, methods=["POST"])
        self.app.add_url_rule("/delete_group", view_func=self.handle_delete_group, methods=["POST"])
        
        self.app.add_url_rule("/link_project", view_func=self.handle_link_project, methods=["POST"])
        self.app.add_url_rule("/unlink_project", view_func=self.handle_unlink_project, methods=["POST"])
        self.app.add_url_rule("/list_projects", view_func=self.return_linked_projects, methods=["GET"])
    
    def user_heartbeat(self):
        """
        Runs on every received request to update the user's last active time.
        """
        if "user" in request.cookies:
            self.store.bump_active(request.cookies["user"])

    
    def return_version(self):
        return Response(aux_server.__version__, mimetype="text/plain")

    def handle_connection(self):
        return 'You are connected!'

    def handle_disconnection(self):
        if "user" in request.cookies:
            success, error_message = self.store.disconnect_user(request.cookies["user"])
            if success:
                return 'You have disconnected!'
            else:
                return Response(error_message, 400)
        else:
            return Response("Missing Username", 400)

    def receive_function(self):
        if "user" in request.cookies: # Can't keep track of users if they are not associated with a username
            username = request.cookies["user"]
            if "address" in request.form:
                addr = int(request.form["address"])
            else:
                addr = None

            if "function_address" in request.form:
                func_addr = int(request.form["function_address"])
            else:
                func_addr = None

            self.store.setUserLocation(username, addr, func_addr)
        l.info("%s", self.store.get_user_data())
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
            user_data = self.store.get_user_data(int(etag[1:-1]))
            if user_data is None: # User data unchanged
                return Response(status=304)
        else:
            # Guaranteed not None because no count provided
            user_data = self.store.get_user_data()
        resp = jsonify(user_data[0]) # pyright: ignore[reportOptionalSubscript]
        resp.set_etag(str(user_data[1])) # pyright: ignore[reportOptionalSubscript]
        return resp
        
    def handle_create_group(self):
        '''
        Creates a group.
        '''
        if "group" in request.form:
            result = self.store.create_group(request.form["group"])
            if result[0] == True:
                return Response("OK", 200)
            else:
                return Response(result[1], 500)
        else:
            return Response("Missing group", 400)
    
    def handle_delete_group(self):
        '''
        Deletes a group and all projects linked within it.
        '''
        if "group" in request.form:
            result = self.store.delete_group(request.form["group"])
            if result[0] == True:
                return Response("OK", 200)
            else:
                return Response(result[1], 500)
        else:
            return Response("Missing group", 400)
        
    def handle_link_project(self):
        '''
        Links a project into the server based on Git url (with optional Group specifier)
        
        Expected form parameters: url (mandatory) and group (optional, assumed to be None)
        '''
        if "url" in request.form:
            url = request.form["url"]
            if "group" in request.form:
                result = self.store.link_project(url, request.form["group"])
            else:
                result = self.store.link_project(url)
            if result[0] == True:
                return Response("OK", 200)
            else:
                return Response(result[1], 500)
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
        self.stop_event = threading.Event()
        self.cleaning_thread = threading.Thread(target=self.store.clean_inactive_loop, args=(self.stop_event, self.inactive_poll_sec, self.inactive_timeout_sec))
        self._wz_server = make_server(self.host, self.port, self.app)
        l.info("Server starting!")
        self.cleaning_thread.start()
        self._wz_server.serve_forever()

        # Stop if werkzeug server has stopped serving
        self._wz_server = None
        self.stop()

    def stop(self):
        self.stop_event.set()
        if self._wz_server is not None:
            self._wz_server.shutdown()
        self.cleaning_thread.join()

    