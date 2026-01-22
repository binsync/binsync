from collections import defaultdict
from queue import Queue
from threading import Lock
import logging

l = logging.getLogger(__name__)


class Cache:
    def __init__(self, master_user=None):
        self.state_cache = defaultdict(StateCache)
        self.user_cache = UserCache()
        self.state_lock = Lock()
        self.user_lock = Lock()

        self.master_state_lock = Lock()
        self._master_user = master_user
        self._master_state = None
        self.queued_master_state_changes = Queue()

        # key: (func_addr, user) to value: diff_dict
        self.diff_cache = {}
        self.diff_lock = Lock()

    def clear_state_cache(self, username_commit_dict: dict):
        for username, commit in username_commit_dict.items():
            # master user should never have state erased
            if not username or username == self._master_user:
                continue

            with self.state_lock:
                if self.state_cache[username].commit != commit:
                    self.state_cache[username].state = None
                    self.state_cache[username].commit = commit
            
            self.clear_diffs(user=username)

    def clear_user_branch_cache(self, branch_set: set):
        with self.user_lock:
            if branch_set != self.user_cache.known_branches:
                # master user is always known
                self.user_cache.users = [self._master_user]
                self.user_cache.known_branches = branch_set

    #
    # getters
    #

    def get_state(self, user=None, **kwargs):
        if not user or user == self._master_user:
            with self.master_state_lock:
                return self._master_state.copy() if self._master_state else None
        else:
            with self.state_lock:
                state = self.state_cache[user].state
                return state.copy() if state else state

    def users(self, **kwargs):
        with self.user_lock:
            return self.user_cache.users if self.user_cache.users else []
    
    def get_diff(self, func_addr, user):
        with self.diff_lock:
            cache_key = (func_addr, user)
            return self.diff_cache.get(cache_key)

    #
    # setters
    #

    def set_state(self, state, user=None, **kwargs):
        copied_state = state.copy()
        if not user or user == self._master_user:
            with self.master_state_lock:
                self.queued_master_state_changes.put_nowait(copied_state)
                self._master_state = copied_state
        else:
            with self.state_lock:
                self.state_cache[user].state = copied_state

    def set_users(self, users, **kwargs):
        with self.user_lock:
            self.user_cache.users = users
    
    def set_diff(self, func_addr, user, diff):
        with self.diff_lock:
            cache_key = (func_addr, user)
            self.diff_cache[cache_key] = diff
    

    #
    # cache utils
    #

    def clear_diffs(self, user=None, func_addr=None):
        with self.diff_lock:
            if user is None and func_addr is None:
                # clear all cache
                self.diff_cache.clear()
            elif func_addr is not None and user is not None:
                # clear specific diff
                cache_key = (func_addr, user)
                if cache_key in self.diff_cache:
                    del self.diff_cache[cache_key]
            elif user is not None:
                # clear all diffs for the user
                keys_removal = [key for key in self.diff_cache.keys() if key[1] == user]
                for key in keys_removal:
                    del self.diff_cache[key]


class StateCache:
    def __init__(self, state=None, commit=None):
        self.state = state
        self.commit = commit


class UserCache:
    def __init__(self, users=None):
        self.users = users
        self.known_branches = set()