from typing import Optional
import logging

from binsync.api.controller import BSController, init_checker, fill_event
from binsync.data import (
    Function, FunctionHeader, StackVariable, Comment
)

from .ghidra_client import BSGhidraClient
from .artifact_lifter import GhidraArtifactLifter

l = logging.getLogger(__name__)


class GhidraBSController(BSController):
    def __init__(self):
        super(GhidraBSController, self).__init__(GhidraArtifactLifter(self))
        self.ghidra = BSGhidraClient()
        self.base_addr = None

    def binary_hash(self) -> str:
        return self.ghidra.binary_hash

    def active_context(self):
        return self.ghidra.context()

    def binary_path(self) -> Optional[str]:
        return self.ghidra.binary_path

    def get_func_size(self, func_addr) -> int:
        return 0

    def rebase_addr(self, addr, up=True):
        if self.base_addr is None:
            self.base_addr = self.ghidra.base_addr

        if up:
            if addr > self.base_addr:
                return
            return addr + self.base_addr
        elif addr > self.base_addr:
            return addr - self.base_addr

    def goto_address(self, func_addr) -> None:
        self.ghidra.goto_address(func_addr)

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
        update = False
        stack_var: StackVariable = artifact
        if stack_var.name:
            update |= self.ghidra.set_stack_var_name(stack_var.addr, stack_var.offset, stack_var.name)

        if stack_var.type:
            update |= self.ghidra.set_stack_var_type(stack_var.addr, stack_var.offset, stack_var.type)

        return update

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, **kwargs):
        update = False
        func_header: FunctionHeader = artifact
        if func_header.name:
            update |= self.ghidra.set_func_name(func_header.addr, func_header.name)

        if func_header.type:
            update |= self.ghidra.set_func_rettype(func_header.addr, func_header.type)

        return update

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        update = False
        comment: Comment = artifact
        if comment.comment:
            update |= self.ghidra.set_comment(comment.addr, comment.comment, comment.decompiled)

        return update

    @init_checker
    def magic_fill(self, preference_user=None):
        super(GhidraBSController, self).magic_fill(
            preference_user=preference_user, target_artifacts={Function: self.fill_function}
        )
