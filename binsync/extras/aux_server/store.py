import threading
from copy import deepcopy

class User:
    def __init__(self):
        self._addr = None
        self._func_addr = None
    
    def update_location(self, addr:int|None, func_addr:int|None):
        self._addr = addr
        self._func_addr = func_addr
    
    def get_location(self):
        """
        Returns _addr and _func_addr as a dict of {"addr": _addr, "func_addr": _func_addr}
        """
        return {"addr": self._addr, "func_addr": self._func_addr}

class ServerStore:
    DEFAULT_GROUPNAME = "default"
    def __init__(self):
        self._user_count = 0
        self._user_map:dict[str, User] = {}
        self._map_modify_count = 0 # Counter to help minimize unnecessary requests on a fetch

        # We use a dict for the projects in each group so that we can preserve order while retaining fast access
        self._linked_projects:dict[str,dict[str,None]] = {ServerStore.DEFAULT_GROUPNAME: {}} 
        
        self._user_count_lock = threading.Lock()
        # Lock for both _user_map and _map_modify_count
        self._user_map_lock = threading.Lock()
        self._linked_projects_lock = threading.Lock()
       
        
    def incrementUser(self):
        with self._user_count_lock:
            self._user_count+=1
    
    def decrementUser(self):
        with self._user_count_lock:
            self._user_count-=1
    
    def setUserLocation(self, username:str, addr:int|None, func_addr:int|None):
        with self._user_map_lock:
            if username in self._user_map:
                self._user_map[username].update_location(addr, func_addr)
            else:
                new_user = User()
                new_user.update_location(addr, func_addr)
                self._user_map[username] = new_user
            self._map_modify_count += 1
    
    def getUserData(self, count=None)->tuple[dict[str, dict[str, int | None]], int]|None:
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