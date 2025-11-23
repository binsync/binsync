import urllib.parse
import requests
import logging
import time
from libbs.artifacts import (
    Context
)
l = logging.getLogger(__name__)

class ServerClient():
    def __init__(self, host:str, port:int, controller, worker_update_callback):
        self.host = host
        self.port = str(port)
        self.controller = controller
        self.old_post_data = {}
        self.worker_update_callback = worker_update_callback
        
    def run(self):
        self.server_url = f"http://{self.host}:{self.port}"
        self._etag = None
        parsed = urllib.parse.urlparse(self.server_url)
        if parsed.netloc != f"{self.host}:{self.port}":
            l.error("HOST AND PORT COMBINATION IS NOT VALID: NETLOC %s BUT HOST %s AND PORT %s",parsed.netloc,parsed.hostname,parsed.port)
        self._manage_connections()

    def _manage_connections(self):
        self.sess = requests.Session()
        callback_registered = False
        try:
            l.info(self.sess.get(self.server_url+"/connect").text)
            self.connected = True
            
            # Register callback to broadcast function context
            self.controller.deci.artifact_change_callbacks[Context].append(self._submit_new_context)
            callback_registered = True
            
            # Broadcast the starting context upon connection with server
            self._submit_new_context(self.controller.deci.gui_active_context())
            
            while self.connected:
                self._poll_users_data()
                time.sleep(1)
            l.info(self.sess.get(self.server_url+"/disconnect").text)
        except requests.ConnectionError:
            l.info("Server seems to be unresponsive... (Click the disconnect button so that you can reconnect)")
        finally:
            # De-register callback to broadcast function context
            if callback_registered:
                self.controller.deci.artifact_change_callbacks[Context].remove(self._submit_new_context)
    
    def _poll_users_data(self):
        """
        Contacts server to check if there were any updates to user contexts
        """
        if self._etag == None:
            r = self.sess.get(self.server_url+"/status")
            self.users_data = r.json()
            self._etag = r.headers["ETag"]
            l.info(self.users_data)
            self.worker_update_callback(self.users_data)
        else:
            r = self.sess.get(self.server_url+"/status",headers={
                "If-None-Match":str(self._etag)
            })
            if r.status_code != 304:
                self.users_data = r.json()
                self._etag = r.headers["ETag"]
                l.info(self.users_data)
                self.worker_update_callback(self.users_data)
    
    def _submit_new_context(self, context, **_):
        post_data = {}
        if context.addr:
            post_data["address"] = context.addr
        if context.func_addr:
            post_data["function_address"] = context.func_addr
        if self.controller.client:
            post_data["username"] = self.controller.client.master_user
        if post_data != self.old_post_data: # No need to do extra communication with server if no change
            try:
                self.sess.post(self.server_url+"/function",data=post_data)
                self.old_post_data = post_data
            except requests.ConnectionError:
                self.connected = False

    def stop(self):
        self.connected = False