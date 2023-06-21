from typing import Optional
import logging

from binsync.api.controller import BSController, init_checker, fill_event
from binsync.data import (
    Function, FunctionHeader, StackVariable, Comment
)

from .artifact_lifter import GhidraArtifactLifter
from .ghidra_api import GhidraAPIWrapper

l = logging.getLogger(__name__)


class GhidraBSController(BSController):
    def __init__(self, **kwargs):
        super(GhidraBSController, self).__init__(GhidraArtifactLifter(self), **kwargs)
        self.ghidra = None
        self._last_addr = None
        self._last_func = None
        self.base_addr = None

    def connect_ghidra_bridge(self):
        self.ghidra = GhidraAPIWrapper(self)
        return self.ghidra.connected

    def binary_hash(self) -> str:
        return self.ghidra.currentProgram.executableMD5

    def active_context(self):
        active_addr = self.ghidra.currentLocation.getAddress().getOffset()
        if active_addr is None:
            return Function(0, 0)

        if active_addr != self._last_addr:
            self._last_addr = active_addr
            self._last_func = self.gfunc_to_bsfunc(self._get_nearest_function(active_addr))

        return self._last_func

    def binary_path(self) -> Optional[str]:
        return self.ghidra.currentProgram.executablePath

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

    def _decompile(self, function: Function) -> Optional[str]:
        return self.ghidra.decompile(function.addr)

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
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        update = False
        update |= self.ghidra.set_global_var_name(var_addr, artifact.name)
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

    #
    # Artifact API
    #

    def _decompile(self, function: Function) -> Optional[str]:
        return None

    @staticmethod
    def dict_to_stackvars(variables) -> dict:
        stack_vars = {}
        for offset in variables:
            sv = StackVariable(None, None, None, None, None)
            stack_vars[offset] = sv.__setstate__(variables[offset])
        return stack_vars

    def function(self, addr, **kwargs) -> Optional[Function]:
        ret = self.ghidra.get_function(addr)
        if not ret:
            return None
        return Function.parse(ret)

    def functions(self, **kwargs) -> dict:
        ret = self.ghidra.get_functions()
        funcs = {}
        if not ret:
            return funcs
        for addr in ret:
            stack_vars = self.dict_to_stackvars(ret[addr]["stack_vars"])
            funcs[addr] = Function(addr, ret[addr]["size"], header=FunctionHeader(ret[addr]["name"], addr), stack_vars=stack_vars)
        return funcs

    def stack_vars(self, addr, **kwargs) -> dict:
        ret = self.ghidra.get_stack_vars(addr)
        if not ret:
            return {}
        return self.dict_to_stackvars(ret)

    def _get_nearest_function(self, addr: int):
        func_manager = self.ghidra.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self.ghidra.toAddr(addr))

    def gfunc_to_bsfunc(self, gfunc):
        if gfunc is None:
            return None

        bs_func = Function(
            gfunc.getEntryPoint().getOffset(), gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(gfunc.getName(), gfunc.getEntryPoint().getOffset())
        )
        return bs_func
