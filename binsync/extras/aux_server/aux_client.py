import urllib.parse
import requests
import logging
import time
from libbs.artifacts import (
    Context
)
l = logging.getLogger(__name__)

def _connection_required(func):
    def check_for_connected(self, *args, **kwargs):
        if self.connected:
            try:
                return func(self, *args, **kwargs)
            except requests.ConnectionError:
                self.connected = False
                l.info("Server seems to be unresponsive... (Click the disconnect button so that you can reconnect)")
        else:
            l.error("Tried to call a method that requires a connection to be established beforehand") 
        
    return check_for_connected

class ServerClient():
    def __init__(self, host:str, port:int, controller):
        self.host = host
        self.port = str(port)
        self.controller = controller
        self.old_post_data = {}
        self.connected = False
        self.callback_registered = False
        
    
    
    def connect(self):
        self.server_url = f"http://{self.host}:{self.port}"
        self._etag = None
        parsed = urllib.parse.urlparse(self.server_url)
        if parsed.netloc != f"{self.host}:{self.port}":
            l.error("HOST AND PORT COMBINATION IS NOT VALID: NETLOC %s BUT HOST %s AND PORT %s",parsed.netloc,parsed.hostname,parsed.port)
        self.sess = requests.Session()
        l.info(self.sess.get(self.server_url+"/connect").text)
        self.connected = True
        self.controller.deci.artifact_change_callbacks[Context].append(self._submit_new_context)
        self.callback_registered = True
        self._submit_new_context(self.controller.deci.gui_active_context())
        return True

    @_connection_required
    def poll_users_data(self):
        """
        Contacts server to check if there were any updates to user contexts
        """
        if self._etag == None:
            r = self.sess.get(self.server_url+"/status")
            self.users_data = r.json()
            self._etag = r.headers["ETag"]
            l.info(self.users_data)
        else:
            r = self.sess.get(self.server_url+"/status",headers={
                "If-None-Match":str(self._etag)
            })
            if r.status_code != 304:
                self.users_data = r.json()
                self._etag = r.headers["ETag"]
                l.info(self.users_data)
        return self.users_data
    
    @_connection_required
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

    @_connection_required
    def _link_project(self, url, group=None):
        '''
        Attempts to link a project to the server. 
        
        Returns (True,"") on success (200 response) and (False,"error message") on error
        '''
        post_data = {
            "url":url 
        }
        if group is not None:
            post_data[group] = group
        result = self.sess.post(self.server_url+"/link_project", data=post_data)
        if result.status_code == 200:
            return (True, "")
        else:
            return (False, result.text)

    @_connection_required
    def create_group(self, group):
        '''
        Attempts to create a project group.
        
        Returns (True,"") on success (200 response) and (False,"error message") on error
        '''
        post_data = {
            "group": group
        }
        result = self.sess.post(self.server_url+"/create_group", data=post_data)
        if result.status_code == 200:
            return (True, "")
        else:
            return (False, result.text)
        
    @_connection_required
    def delete_group(self, group):
        '''
        Attempts to delete a project group.
        
        Returns (True,"") on success (200 response) and (False,"error message") on error
        '''
        post_data = {
            "group": group
        }
        result = self.sess.post(self.server_url+"/delete_group", data=post_data)
        if result.status_code == 200:
            return (True, "")
        else:
            return (False, result.text)

    @_connection_required
    def link_project(self, url, group=None):
        '''
        Attempts to link a project to the server. 
        
        Returns (True,"") on success (200 response) and (False,"error message") on error
        '''
        post_data = {
            "url":url 
        }
        if group is not None:
            post_data["group"] = group
        result = self.sess.post(self.server_url+"/link_project", data=post_data)
        if result.status_code == 200:
            return (True, "")
        else:
            return (False, result.text)
    
    @_connection_required
    def unlink_project(self, url, group=None):
        '''
        Attempts to unlink a project from the server. 
        
        Returns (True,"") on success (200 response) and (False,"error message") on error
        '''
        post_data = {
            "url":url 
        }
        if group is not None:
            post_data["group"] = group
        result = self.sess.post(self.server_url+"/unlink_project", data=post_data)
        if result.status_code == 200:
            return (True, "")
        else:
            return (False, result.text)
        
    @_connection_required
    def list_projects(self):
        result = self.sess.get(self.server_url+"/list_projects")
        return result.json()

    def stop(self):
        if self.callback_registered:
            self.controller.deci.artifact_change_callbacks[Context].remove(self._submit_new_context)
            self.callback_registered = False
        if self.connected:
            try:
                l.info(self.sess.get(self.server_url+"/disconnect").text)
            except requests.ConnectionError:
                l.info("Server unresponsive")
            self.connected = False
        else:
            l.info("Disconnected without contacting server as it was previously unreachable")