from typing import Optional
import logging

from binsync.common.controller import BinSyncController, init_checker, fill_event
from binsync.core.scheduler import SchedSpeed
from binsync.data import (
    Function, FunctionHeader, StackVariable, Comment
)

from .ghidra_client import BSGhidraClient
from .artifact_lifter import GhidraArtifactLifter

l = logging.getLogger(__name__)


class GhidraBinSyncController(BinSyncController):
    def __init__(self):
        super(GhidraBinSyncController, self).__init__(GhidraArtifactLifter(self))
        self.ghidra = BSGhidraClient()

    def binary_hash(self) -> str:
        return ""

    def active_context(self):
        if not self.ghidra.server:
            return Function(0, 0, header=FunctionHeader("", 0))

        out = self.ghidra.server.context()
        if not out:
            return Function(0, 0, header=FunctionHeader("", 0))

        #return Function(out['func_addr'], 0, header=FunctionHeader(out["name"], out['func_addr']))
        addr = int(out, 16)
        return Function(addr, 0, header=FunctionHeader("", addr))

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

    def goto_address(self, func_addr) -> None:
        pass

    #
    # Ghidra Specific
    #

    def connect_ghidra_client(self):
        return self.ghidra.connect()

    def alert_ghidra_ui_configured(self):
        status = True if self.check_client() else False
        self.ghidra.alert_ui_configured(status)

    #
    # BinSync API
    #

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, **kwargs):
        ret = False
        stack_var: StackVariable = artifact
        if stack_var.name:
            ret |= self.ghidra.set_stack_var_name(stack_var.addr, stack_var.stack_offset, stack_var.name)

        if stack_var.type:
            ret |= self.ghidra.set_stack_var_type(stack_var.addr, stack_var.stack_offset, stack_var.type)
        return ret

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, **kwargs):
        func_header: FunctionHeader = artifact
        return self.ghidra.set_func_name(func_header.addr, func_header.name)

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        return False

    @init_checker
    def magic_fill(self, preference_user=None):
        super(GhidraBinSyncController, self).magic_fill(
            preference_user=preference_user, target_artifacts={Function: self.fill_function}
        )
