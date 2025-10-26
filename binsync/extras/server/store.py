import threading
from copy import deepcopy
class ServerStore:
    def __init__(self):
        self._user_count = 0
        self._user_map = {}
        self._user_count_lock = threading.Lock()
        self._user_map_lock = threading.Lock()
        
    def incrementUser(self):
        with self._user_count_lock:
            self._user_count+=1
    
    def decrementUser(self):
        with self._user_count_lock:
            self._user_count-=1
    
    def setUserData(self,username,newData):
        with self._user_map_lock:
            self._user_map[username] = newData
            
    def getUserData(self):
        with self._user_map_lock:
            map_copy = deepcopy(self._user_map)
        return map_copy