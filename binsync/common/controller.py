from functools import wraps
import threading
import time
import datetime
import logging
from typing import Optional, Iterable, Dict, List
from collections import OrderedDict

from ..client import Client
from ..data import User, Function, StackVariable, Comment, Struct

_l = logging.getLogger(name=__name__)


#
# State Checking Decorators
#


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if not self.check_client():
            raise RuntimeError("Please connect to a repo first.")
        return f(self, *args, **kwargs)

    return initcheck


def make_state(f):
    """
    Build a writeable State _instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """

    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            state = self.client.get_state(user=user)
            kwargs['state'] = state
            r = f(self, *args, **kwargs)
            state.save()
        else:
            kwargs['state'] = state
            r = f(self, *args, **kwargs)

        return r

    return state_check


def make_ro_state(f):
    """
    Build a read-only State _instance and pass to `f` as the `state` kwarg if the `state` kwarg is None.
    Function `f` should have have at least two kwargs, `user` and `state`.
    """

    @wraps(f)
    def state_check(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        user = kwargs.pop('user', None)
        if state is None:
            state = self.client.get_state(user=user)
        kwargs['state'] = state
        kwargs['user'] = user
        return f(self, *args, **kwargs)

    return state_check

#
# Description Classes
#

class SyncControlStatus:
    CONNECTED = 0
    CONNECTED_NO_REMOTE = 1
    DISCONNECTED = 2


#
#   Controller
#

class BinSyncController:
    def __init__(self, headless=False):
        # client created on connection
        self.client = None  # type: Optional[Client]

        # ui callback created on UI init
        self.headless = headless
        self.ui_callback = None
        self._last_reload = datetime.datetime.now()

        # command locks
        self.queue_lock = threading.Lock()
        self.cmd_queue = OrderedDict()

        # create a pulling thread, but start on connection
        self.pull_thread = threading.Thread(target=self.pull_routine)

    #
    #   Multithreading locks and setters
    #

    def make_controller_cmd(self, cmd_func, *args, **kwargs):
        with self.queue_lock:
            self.cmd_queue[time.time()] = (cmd_func, args, kwargs)

    def eval_cmd_queue(self):
        cmd = None
        with self.queue_lock:
            if len(self.cmd_queue) > 0:
                # pop the first command from the queue
                cmd = self.cmd_queue.popitem(last=False)[1]

        # parse the command if present
        if not cmd:
            return

        func, f_args, f_kargs = cmd[:]
        func(*f_args, **f_kargs)

    def pull_routine(self):
        while True:
            time.sleep(1)

            # verify the client is connected
            if not self.check_client():
                continue

            # update client every 10 seconds if it has a remote connection
            if self.client.has_remote and (
                    (self.client._last_pull_attempt_at is None) or
                    (datetime.datetime.now() - self.client._last_pull_attempt_at).seconds > 10
            ):
                self.client.pull()

            # evaluate commands started by the user
            self.eval_cmd_queue()

            # update the control panel with new info every 10 seconds
            if not self.headless and (datetime.datetime.now() - self._last_reload).seconds > 10:
                self._last_reload = datetime.datetime.now()
                self.update_ui()

    def update_ui(self):
        if not self.ui_callback:
            return

        self.ui_callback()

    def start_pull_routine(self):
        self.pull_thread.setDaemon(True)
        self.pull_thread.start()

    #
    # Client Interaction Functions
    #

    def connect(self, user, path, init_repo=False, remote_url=None):
        binary_hash = self.get_binary_hash()
        self.client = Client(
            user, path, binary_hash, init_repo=init_repo, remote_url=remote_url
        )

        self.start_pull_routine()
        return self.client.connection_warnings

    def check_client(self):
        return self.client is not None

    def status(self):
        if self.check_client():
            if self.client.has_remote:
                return SyncControlStatus.CONNECTED
            return SyncControlStatus.CONNECTED_NO_REMOTE
        return SyncControlStatus.DISCONNECTED

    def status_string(self):
        stat = self.status()
        if stat == SyncControlStatus.CONNECTED:
            return f"[+] Connected to a remote sync repo: {self.client.master_user}"
        elif stat == SyncControlStatus.CONNECTED_NO_REMOTE:
            return f"[+] Connected to a local sync repo: {self.client.master_user}"
        else:
            return "[!] Not connected to a sync repo"

    @init_checker
    def users(self) -> Iterable[User]:
        return self.client.users()


    #
    # Override Mandatory Functions
    #

    def get_binary_hash(self) -> str:
        raise NotImplementedError


    #
    # Fillers
    #

    @init_checker
    @make_ro_state
    def fill_structs(self, user=None, state=None):
        """
        Grab all the structs from a specified user, then fill them locally

        @param user:
        @param state:
        @return:
        """
        raise NotImplementedError

    @init_checker
    @make_ro_state
    def fill_function(self, func_addr, user=None, state=None):
        """
        Grab all relevant information from the specified user and fill the @func_adrr.
        """
        raise NotImplementedError

    #
    # Pullers
    #

    @init_checker
    @make_ro_state
    def pull_function(self, func_addr, user=None, state=None) -> Function:
        if not func_addr:
            return None

        try:
            func = state.get_function(func_addr)
        except KeyError:
            return None

        return func

    @init_checker
    @make_ro_state
    def pull_stack_variables(self, func_addr, user=None, state=None) -> Dict[int, StackVariable]:
        try:
            return dict(state.get_stack_variables(func_addr))
        except KeyError:
            return {}

    @init_checker
    @make_ro_state
    def pull_stack_variable(self, func_addr, offset, user=None, state=None) -> StackVariable:
        return state.get_stack_variable(func_addr, offset)

    @init_checker
    @make_ro_state
    def pull_comments(self, func_addr, user=None, state=None) -> Dict[int, Comment]:
        try:
            return state.get_comments(func_addr)
        except KeyError:
            return {}

    @init_checker
    @make_ro_state
    def pull_comment(self, func_addr, addr, user=None, state=None) -> Comment:
        try:
            return state.get_comment(func_addr, addr)
        except KeyError:
            return None

    @init_checker
    @make_ro_state
    def pull_structs(self, user=None, state=None) -> List[Struct]:
        """
        Pull structs downwards.

        @param user:
        @param state:
        @return:
        """
        return state.get_structs()

    #
    # Utils
    #

    @staticmethod
    def get_default_type_str(size):
        if size == 1:
            return "unsigned char"
        elif size == 2:
            return "unsigned short"
        elif size == 4:
            return "unsigned int"
        elif size == 8:
            return "unsigned long long"
        else:
            raise Exception("Unable to decide default type string!")

