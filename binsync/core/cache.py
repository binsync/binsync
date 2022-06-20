from collections import defaultdict
from threading import Lock
import logging

l = logging.getLogger(__name__)

class Cache:

    def __init__(self):
        self.state_cache = defaultdict(StateCache)
        self.user_cache = UserCache()
        self.state_lock = Lock()
        self.user_lock = Lock()

    def update_state_cache_commits(self, username_commit_dict: dict):
        for username, commit in username_commit_dict.items():
            with self.state_lock:
                if self.state_cache[username].commit != commit:
                    self.state_cache[username].state = None
                    self.state_cache[username].commit = commit

    def update_user_cache_branches(self, branch_set: set):
        with self.user_lock:
            if branch_set != self.user_cache.known_branches:
                self.user_cache.users = None
                self.user_cache.known_branches = branch_set

    #
    # getters
    #

    def get_state(self, user=None, **kwargs):
        with self.state_lock:
            return self.state_cache[user].state

    def users(self, **kwargs):
        with self.user_lock:
            return self.user_cache.users

    #
    # setters
    #

    def set_state(self, state, user=None, **kwargs):
        with self.state_lock:
            self.state_cache[user].state = state

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