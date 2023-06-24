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
        self.ghidra: Optional[GhidraAPIWrapper] = None
        self._last_addr = None
        self._last_func = None
        self.base_addr = None

    def _init_headless_components(self):
        self.connect_ghidra_bridge()

    #
    # Controller API
    #

    def binary_hash(self) -> str:
        return self.ghidra.currentProgram.executableMD5

    def active_context(self):
        active_addr = self.ghidra.currentLocation.getAddress().getOffset()
        if active_addr is None:
            return Function(0, 0)

        if active_addr != self._last_addr:
            self._last_addr = active_addr
            self._last_func = self._gfunc_to_bsfunc(self._get_nearest_function(active_addr))

        return self._last_func

    def binary_path(self) -> Optional[str]:
        return self.ghidra.currentProgram.executablePath

    def get_func_size(self, func_addr) -> int:
        gfunc = self._get_nearest_function(func_addr)
        return int(gfunc.getBody().getNumAddresses())

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
        services = self.ghidra.imports["ghidra.app.services"]
        goto_service_class = services.GoToService.__class__
        go_to_service = self.ghidra.getState().getTool().getService(goto_service_class)
        go_to_service.goTo(self.ghidra.toAddr(func_addr))

    def connect_ghidra_bridge(self):
        self.ghidra = GhidraAPIWrapper(self)
        return self.ghidra.connected

    #
    # Filler/Setter API
    #

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, **kwargs):
        # TODO: set type, name, and args (last)
        return False

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, **kwargs):
        return False

    @fill_event
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        # TODO: set type and name
        return False

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        return False

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

    def function(self, addr, **kwargs) -> Optional[Function]:
        return None

    def functions(self) -> Dict[int, Function]:
        return {}

    def global_var(self, addr) -> Optional[GlobalVariable]:
        return None

    def global_vars(self) -> Dict[int, GlobalVariable]:
        return {}

    #
    # Ghidra Specific API
    #

    def str_type_to_gtype(self, typestr: str) -> Optional["DataType"]:
        return None

    def _get_nearest_function(self, addr: int):
        func_manager = self.ghidra.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self.ghidra.toAddr(addr))

    def _gfunc_to_bsfunc(self, gfunc):
        if gfunc is None:
            return None

        bs_func = Function(
            gfunc.getEntryPoint().getOffset(), gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(gfunc.getName(), gfunc.getEntryPoint().getOffset())
        )
        return bs_func
