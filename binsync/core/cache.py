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

    def clear_state_cache(self, username_commit_dict: dict):
        for username, commit in username_commit_dict.items():
            # master user should never have state erased
            if not username or username == self._master_user:
                continue

            with self.state_lock:
                if self.state_cache[username].commit != commit:
                    self.state_cache[username].state = None
                    self.state_cache[username].commit = commit

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


class StateCache:
    def __init__(self, state=None, commit=None):
        self.state = state
        self.commit = commit


class UserCache:
    def __init__(self, users=None):
        self.users = users
        self.known_branches = set()