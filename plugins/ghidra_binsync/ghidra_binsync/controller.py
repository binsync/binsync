from typing import Optional
import logging

from binsync.common.controller import BinSyncController, init_checker
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
        super(GhidraBinSyncController, self).__init__()
        l.info("Start Ghidra controller")
        self.bridge = BSBridgeClient()

    def binary_hash(self) -> str:
        return ""

    def active_context(self):
        out = self.bridge.server.context()
        if not out:
            return Function(0, 0, header=FunctionHeader("", 0))

        return Function(out['func_addr'], 0, header=FunctionHeader(out["name"], out['func_addr']))

    def binary_path(self) -> Optional[str]:
        return ""

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

    @init_checker
    def magic_fill(self, preference_user=None):
        super(GhidraBinSyncController, self).magic_fill(
            preference_user=preference_user, target_artifacts={Function: self.fill_function}
        )
