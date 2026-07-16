import threading
from copy import deepcopy
import time
import logging
l = logging.getLogger(__name__)

class User:
    def __init__(self):
        self._addr = None
        self._func_addr = None

        # The last time the user contacted the server in seconds since the Epoch
        self._last_active = time.time()
    
    def update_location(self, addr:int|None, func_addr:int|None):
        self._addr = addr
        self._func_addr = func_addr
    
    def get_location(self):
        """
        Returns _addr and _func_addr as a dict of {"addr": _addr, "func_addr": _func_addr}
        """
        return {"addr": self._addr, "func_addr": self._func_addr}

    def update_active(self):
        """
        Updates the last active time of the user with the current time.
        """
        self._last_active = time.time()

    def get_active(self):
        """
        Returns the last time the user was active.
        """
        return self._last_active
    
    def __str__(self):
        return f"Address: {self._addr}, function address: {self._func_addr}, last active: {self._last_active}"

class ServerStore:
    DEFAULT_GROUPNAME = "default"
    def __init__(self):
        self._user_map:dict[str, User] = {}
        self._map_modify_count = 0 # Counter to help minimize unnecessary requests on a fetch

        # We use a dict for the projects in each group so that we can preserve order while retaining fast access
        self._linked_projects:dict[str,dict[str,None]] = {ServerStore.DEFAULT_GROUPNAME: {}} 
        
        # Lock for both _user_map and _map_modify_count
        self._user_map_lock = threading.Lock()
        self._linked_projects_lock = threading.Lock()
       
    def disconnect_user(self, username):
        """
        Removes a user from the user map. Returns (True, "") on a successful deletion
        and (False, "<error message>") on an unsuccessful deletion (most likely due 
        to the user not being present in the user map).
        """
        with self._user_map_lock:
            try:
                del self._user_map[username]
            except KeyError:
                return (False, f"username {username} not in users")
            l.info("User %s disconnected", username)
            self._map_modify_count += 1
        return (True, "")

    def bump_active(self, username):
        with self._user_map_lock:
            if username in self._user_map:
                self._user_map[username].update_active()
            else:
                self._user_map[username] = User()
    
    def setUserLocation(self, username:str, addr:int|None, func_addr:int|None):
        with self._user_map_lock:
            if username in self._user_map:
                self._user_map[username].update_location(addr, func_addr)
            else:
                new_user = User()
                new_user.update_location(addr, func_addr)
                self._user_map[username] = new_user
            self._map_modify_count += 1
    
    def get_user_data(self, count=None)->tuple[dict[str, dict[str, int | None]], int]|None:
        """
        Gets the user data (dict of username -> [dict of "addr"/"func_addr" to address])
        stored as a tuple alongside the current modification counter.

        If the modification counter matches the provided count, instead returns None.
        (If no count provided, will always return user data)

        It is safe to modify the returned data however you want because the locations
        are primitive data types that are copied.
        """
        with self._user_map_lock:
            if self._map_modify_count != count:
                map_copy = {username: user.get_location() for username, user in self._user_map.items()}
                return (map_copy, self._map_modify_count)
        return None
    
    def create_group(self, group)->tuple[bool,str]:
        with self._linked_projects_lock:
            if group not in self._linked_projects:
                self._linked_projects[group] = {}
                return (True, "")
            else:
                return (False, "group already exists")
    
    def delete_group(self, group)->tuple[bool,str]:
        with self._linked_projects_lock:
            if group in self._linked_projects:
                if group != ServerStore.DEFAULT_GROUPNAME:
                    del self._linked_projects[group]
                    return (True, "")
                else:
                    return (False, "cannot delete default group")
            else:
                return (False, "group does not exist")
    
    def link_project(self, url, group=DEFAULT_GROUPNAME)->tuple[bool,str]:
        with self._linked_projects_lock:
            if group in self._linked_projects:
                curr_group = self._linked_projects[group]
                if url not in curr_group:
                    self._linked_projects[group][url] = None
                    return (True, "")
                else:
                    return (False, "project already exists in group")
            else:
                return (False, "group does not exist")
    
    def unlink_project(self, url, group=DEFAULT_GROUPNAME)->tuple[bool,str]:
        '''
        Unlinks a project. 
        
        Returns (True,"") on successful removal. 
        If not in the group specified (or "default" if no group specified), returns (False, "error message"). 
        '''
        with self._linked_projects_lock:
            if group in self._linked_projects:
                curr_group = self._linked_projects[group]
                if url in curr_group:
                    del curr_group[url]
                    return (True, "")
                else:
                    return (False, "project does not exist in group")
            else:
                return (False, "group does not exist")
    
    def list_projects(self):
        # Might want to convert the nested dicts back into lists
        with self._linked_projects_lock:
            return deepcopy(self._linked_projects)
        
    def clean_inactive_loop(self, stop_event: threading.Event, poll_sec:int|float, inactive_timeout_sec:int|float):
        """
        Periodically checks the user map to remove inactive users.
        Do not call this function in the main thread as it will be permanently blocked.

        Checks for inactive users every poll_sec and cleans inactive users who have
        been inactive for at least inactive_timeout_sec. 
        
        Note that the check only occurs every poll_sec, so if poll_sec is 4 and 
        inactive_timeout_sec is 5 then users will be cleaned every 4 * 2 = 8 seconds.
        """
        while not stop_event.is_set():
            current_time = time.time()
            with self._user_map_lock:
                users_to_delete = []
                # Find inactive users
                for username, user in self._user_map.items():
                    if current_time - user.get_active() > inactive_timeout_sec:
                        users_to_delete.append(username)
 
                if len(users_to_delete) > 0:
                    self._map_modify_count += 1

                # Remove inactive users
                for username in users_to_delete:
                    del self._user_map[username]
                    l.info("Removed user %s due to inactivity", username)

            stop_event.wait(poll_sec)
