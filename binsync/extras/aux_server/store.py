import threading
from copy import deepcopy
class ServerStore:
    def __init__(self):
        self._user_count = 0
        self._user_map = {}
        self._user_count_lock = threading.Lock()
        self._user_map_lock = threading.Lock()
        self._map_modify_count = 0 # Counter to help minimize unnecessary requests on a fetch
        
    def incrementUser(self):
        with self._user_count_lock:
            self._user_count+=1
    
    def decrementUser(self):
        with self._user_count_lock:
            self._user_count-=1
    
    def setUserData(self,username,newData):
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