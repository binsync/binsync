from typing import Optional
import logging

from binsync.common.controller import BinSyncController, make_ro_state, init_checker
from binsync.core.scheduler import SchedSpeed
from binsync.data import (
    Function, FunctionHeader
)

from .bridge_client import BSBridgeClient

l = logging.getLogger(__name__)

class GhidraBinSyncController(BinSyncController):
    def __init__(self):
        """
        TODO: add a real lifter as first arg here
        """
        super(GhidraBinSyncController, self).__init__(None)
        l.info("Start Ghidra controller")
        self.bridge = BSBridgeClient()

    def binary_hash(self) -> str:
        return "temp"

    def active_context(self):
        out = self.bridge.server.context()
        if not out:
            return Function(0, 0, header=FunctionHeader("", 0))

        return Function(out['func_addr'], 0, header=FunctionHeader(out["name"], out['func_addr']))

    def binary_path(self) -> Optional[str]:
        return "tmp"

    def get_func_size(self, func_addr) -> int:
        return 0

    def rebase_addr(self, addr, up=True):
        base_addr = 0x100000
        if up:
            return addr + base_addr
        elif addr > base_addr:
            return addr - base_addr

    #
    # Ghidra Specific
    #

    def connect_ghidra_bridge(self):
        self.bridge.connect()

    def alert_ghidra_of_config(self):
        status = True if self.check_client() else False
        self.bridge.set_controller_status(status)

    #
    # BinSync API
    #

    @init_checker
    @make_ro_state
    def fill_function(self, func_addr, user=None, state=None):
        l.info("Inside fill function!")
        sync_func = self.pull_function(func_addr, user=user)
        l.info("pulling a function")
        if sync_func is None:
            l.info("function was none")
            # the function does not exist for that user's state
            return False

        #sync_func = self.generate_func_for_sync_level(sync_func)
        if sync_func.name:
            l.info("setting funciton name now to " + sync_func.name)
            self.bridge.server.set_func_name(sync_func.addr, sync_func.name)

    def fill_struct(self, struct_name, user=None, state=None):
        return False

    def fill_global_var(self, var_addr, user=None, state=None):
        return False

    @init_checker
    def magic_fill(self, preference_user=None):
        l.info(f"Staring a magic sync with a preference for {preference_user}")
        # re-order users for the prefered user to be at the front of the queue (if they exist)
        all_users = list(self.usernames(priority=SchedSpeed.FAST))
        preference_user = preference_user if preference_user else self.client.master_user
        all_users.remove(preference_user)

        #
        # functions
        #

        master_state = self.client.get_state(user=self.client.master_user, priority=SchedSpeed.FAST)

        l.info(f"Magic Syncing Functions...")
        pref_state = self.client.get_state(user=preference_user, priority=SchedSpeed.FAST)
        for func_addr in self.get_all_changed_funcs():
            l.info(f"Looking at func {hex(func_addr)}")
            pref_func = pref_state.get_function(addr=func_addr)
            for user in all_users:
                user_state = self.client.get_state(user=user, priority=SchedSpeed.FAST)
                user_func = user_state.get_function(func_addr)

                if not user_func:
                    continue

                if not pref_func:
                    pref_func = user_func.copy()
                    continue

                pref_func = Function.from_nonconflicting_merge(pref_func, user_func)
                pref_func.last_change = None

            master_state.functions[pref_func.addr] = pref_func
            self.fill_function(pref_func.addr, state=master_state)

        self.client.commit_state(master_state, msg="Magic Sync Funcs Merged")

