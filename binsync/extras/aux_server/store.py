import threading
from copy import deepcopy
class ServerStore:
    DEFAULT_GROUPNAME = "default"
    def __init__(self):
        self._user_count = 0
        self._user_map:dict[str,dict[str,int|None]] = {}
        self._user_count_lock = threading.Lock()
        self._user_map_lock = threading.Lock()
        self._map_modify_count = 0 # Counter to help minimize unnecessary requests on a fetch
        
        self._linked_projects_lock = threading.Lock()
        # We use a dict for the projects in each group so that we can preserve order while retaining fast access
        self._linked_projects:dict[str|None,dict[str,None]] = {ServerStore.DEFAULT_GROUPNAME: {}} 
        
    def incrementUser(self):
        with self._user_count_lock:
            self._user_count+=1
    
    def decrementUser(self):
        with self._user_count_lock:
            self._user_count-=1
    
    def setUserData(self, username:str, newData:dict[str,int|None]):
        with self._user_map_lock:
            self._user_map[username] = newData
            self._map_modify_count += 1
            
    # If getUserData and getUserDataCountNotMatch become more complex, consider changing _user_map_lock to an RLock
    def getUserData(self)->tuple[dict,int]:
        """
        Gets the user data stored as a tuple alongside the current modification counter.
        """
        with self._user_map_lock:
            map_copy = deepcopy(self._user_map)
            return (map_copy,self._map_modify_count)
    
    def getUserDataCountNotMatch(self,count)->tuple[dict,int]|None:
        """
        Gets the user data stored as a tuple alongside the current modification counter.
        
        If the modification counter matches the provided count, instead returns None
        """
        with self._user_map_lock:
            if self._map_modify_count != count:
                map_copy = deepcopy(self._user_map)
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