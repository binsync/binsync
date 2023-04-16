import logging
import os
from typing import Optional, Dict
from pathlib import Path

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator

import binsync
from binsync.api.controller import (
    BSController,
    init_checker,
    fill_event
)
from binsync.data import (
    Function, FunctionHeader, Comment, StackVariable, FunctionArgument
)

from .artifact_lifter import AngrArtifactLifter

l = logging.getLogger(__name__)
try:
    from angrmanagement.ui.views import CodeView
except ImportError:
    l.warning("angr-management module not found... likely running headless.")

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

class AngrBSController(BSController):
    """
    The class used for all pushing/pulling and merging based actions with BinSync data.
    This class is responsible for handling callbacks that are done by changes from the local user
    and responsible for running a thread to get new changes from other users.
    """

    def __init__(self, workspace=None, headless=False, binary_path: Path = None):
        self._workspace = workspace
        if workspace is None and not headless:
            l.critical("The workspace provided is None, which will result in a broken BinSync.")
            return

        self.main_instance = workspace.main_instance if workspace else self
        self._binary_path = Path(binary_path) if binary_path is not None else binary_path
        super().__init__(artifact_lifter=AngrArtifactLifter(self), headless=headless)

    def _init_headless_components(self):
        if self._binary_path is None or not self._binary_path.exists():
            return

        self.project = angr.Project(str(self._binary_path), auto_load_libs=False)
        cfg = self.project.analyses.CFG(show_progressbar=True, normalize=True, data_references=True)
        self.project.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

    def binary_hash(self) -> str:
        return self.main_instance.project.loader.main_object.md5.hex()

    def active_context(self):
        curr_view = self._workspace.view_manager.current_tab
        if not curr_view:
            return None

        try:
            func = curr_view.function
        except NotImplementedError:
            return None

        if func is None or func.am_obj is None:
            return None

        func_addr = self.rebase_addr(func.addr)

        return binsync.data.Function(
            func_addr, 0, header=FunctionHeader(func.name, func_addr)
        )

    def binary_path(self) -> Optional[str]:
        try:
            return self.main_instance.project.loader.main_object.binary
        # pylint: disable=broad-except
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        try:
            func = self.main_instance.project.kb.functions[func_addr]
            return func.size
        except KeyError:
            return 0

    def rebase_addr(self, addr, up=False):
        base_addr = self.main_instance.project.loader.main_object.mapped_base
        is_pie = self.main_instance.project.loader.main_object.pic

        if is_pie:
            if up:
                return addr + base_addr
            elif addr > base_addr:
                return addr - base_addr

        return addr

    def goto_address(self, func_addr):
        self._workspace.jump_to(self.rebase_addr(func_addr, up=True))

    #
    # Display Fillers
    #

    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        return False

    def fill_struct(self, struct_name, user=None, artifact=None, **kwargs):
        return False

    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        func: Function = artifact
        angr_func = self.main_instance.project.kb.functions[func.addr]

        # re-decompile a function if needed
        decompilation = self.decompile_function(angr_func)

        changes = super(AngrBSController, self).fill_function(
            func_addr, user=user, artifact=artifact, decompilation=decompilation, **kwargs
        )

        self.refresh_decompilation(func.addr)
        return changes

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, decompilation=None, **kwargs):
        cmt: Comment = artifact
        changed = False

        if cmt.decompiled:
            try:
                pos = decompilation.map_addr_to_pos.get_nearest_pos(cmt.addr)
                corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
            # pylint: disable=broad-except
            except Exception:
                return False

            dec_cmt = decompilation.stmt_comments.get(corrected_addr, None)
            if dec_cmt != cmt.comment:
                decompilation.stmt_comments[corrected_addr] = cmt.comment
                changed = True
        else:
            kb_cmt = self.main_instance.project.kb.comments.get(cmt.addr, None)
            if kb_cmt != cmt.comment:
                self.main_instance.project.kb.comments[cmt.addr] = cmt.comment
                changed = True
        return changed

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, decompilation=None, **kwargs):
        sync_var: StackVariable = artifact
        changed = False
        code_var = AngrBSController.find_stack_var_in_codegen(decompilation, offset)
        if code_var:
            code_var.name = sync_var.name
            code_var.renamed = True
            changed = True

        return changed

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, decompilation=None, **kwargs):
        func_header: FunctionHeader = artifact
        angr_func = self.main_instance.project.kb.functions[self.artifact_lifer.lower_addr(func_addr)]
        changes = False
        if func_header:
            if func_header.name and func_header.name != angr_func.name:
                angr_func.name = func_header.name
                decompilation.cfunc.name = func_header.name
                decompilation.cfunc.demangled_name = func_header.name
                changes = True

            if func_header.args:
                for i, arg in func_header.args.items():
                    if i >= len(decompilation.cfunc.arg_list):
                        break
                    if decompilation.cfunc.arg_list[i].variable.name != arg.name:
                        decompilation.cfunc.arg_list[i].variable.name = arg.name
                        changes = True
        return changes

    #
    # Artifact
    #

    def functions(self) -> Dict[int, Function]:
        funcs = {}
        for addr, func in self.main_instance.project.kb.functions.items():
            funcs[addr] = Function(addr, func.size)
            funcs[addr].name = func.name

        return funcs

    def function(self, addr, **kwargs) -> Optional[Function]:
        try:
            _func = self.main_instance.project.kb.functions[addr]
        except KeyError:
            return None

        func = Function(_func.addr, _func.size)
        func.header = FunctionHeader(
            _func.name, _func.addr, type_=_func.prototype.returnty.c_repr() if _func.prototype else None
        )

        decompilation = self.decompile_function(_func)
        if not decompilation:
            return func

        func.header.args = self.func_args_as_bs_args(decompilation)
        # overwrite type again since it can change with decompilation
        func.header.type = decompilation.cfunc.functy.returnty.c_repr()
        stack_vars = {
            angr_sv.offset: StackVariable(
                angr_sv.offset, angr_sv.name, self.stack_var_type_str(decompilation, angr_sv), angr_sv.size, func.addr
            )
            for angr_sv in self.stack_vars_in_dec(decompilation)
        }
        func.stack_vars = stack_vars

        return func

    def _decompile(self, function: Function) -> Optional[str]:
        func = self.main_instance.project.kb.functions.get(function.addr, None)
        if func is None:
            return None

        codegen = self.decompile_function(func)
        if not codegen or not codegen.text:
            return None

        return codegen.text

    #
    #   Utils
    #

    def refresh_decompilation(self, func_addr):
        self.main_instance.workspace.jump_to(func_addr)
        view = self.main_instance.workspace._get_or_create_view("pseudocode", CodeView)
        view.codegen.am_event()
        view.focus()

    def _headless_decompile(self, func):
        cfg = self.project.kb.cfgs.get_most_accurate()
        self.project.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        options = [([
            o for o in angr.analyses.decompiler.decompilation_options.options
            if o.param == "structurer_cls"
        ][0], "phoenix")]

        self.main_instance.project.analyses.Decompiler(
            func, flavor='pseudocode', options=options, optimization_passes=all_optimization_passes
        )


    def _angr_management_decompile(self, func):
        # recover direct pseudocode
        self.main_instance.project.analyses.Decompiler(func, flavor='pseudocode')

        # attempt to get source code if its available
        source_root = None
        if self.main_instance.original_binary_path:
            source_root = os.path.dirname(self.main_instance.original_binary_path)
        self.main_instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

    def decompile_function(self, func, refresh_gui=False):
        # check for known decompilation
        available = self.main_instance.project.kb.structured_code.available_flavors(func.addr)
        should_decompile = False
        if 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self.main_instance.project.kb.structured_code[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        if should_decompile:
            if not self.headless:
                self._angr_management_decompile(func)
            else:
                self._headless_decompile(func)

        # grab newly cached pseudocode
        decomp = self.main_instance.project.kb.structured_code[(func.addr, 'pseudocode')].codegen

        # refresh the UI after decompiling
        if refresh_gui and not self.headless:
            self._workspace.reload()

            # re-decompile current view to cause a refresh
            current_tab = self._workspace.view_manager.current_tab
            if isinstance(current_tab, CodeView) and current_tab.function == func:
                self._workspace.decompile_current_function()

        return decomp

    #
    # Function Data Helpers
    #

    @staticmethod
    def find_stack_var_in_codegen(decompilation, stack_offset: int) -> Optional[angr.sim_variable.SimStackVariable]:
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset") and var.offset == stack_offset:
                return var

        return None

    @staticmethod
    def stack_var_type_str(decompilation, stack_var: angr.sim_variable.SimStackVariable):
        try:
            var_type = decompilation.cfunc.variable_manager.get_variable_type(stack_var)
        # pylint: disable=broad-except
        except Exception:
            return None

        return var_type.c_repr()

    @staticmethod
    def stack_vars_in_dec(decompilation):
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset"):
                yield var

    @staticmethod
    def func_args_as_bs_args(decompilation) -> Dict[int, FunctionArgument]:
        args = {}
        if not decompilation.cfunc.arg_list:
            return args
        
        for idx, arg in enumerate(decompilation.cfunc.arg_list):
            args[idx] = FunctionArgument(
                idx, arg.variable.name, arg.variable_type.c_repr(), arg.variable.size
            )

        return args

    @staticmethod
    def func_insn_addrs(func: angr.knowledge_plugins.Function):
        insn_addrs = set()
        for block in func.blocks:
            insn_addrs.update(block.instruction_addrs)

        return insn_addrs

    def get_closest_function(self, addr):
        try:
            func_addr = self._workspace.main_instance.project.kb.cfgs.get_most_accurate()\
                .get_any_node(addr, anyaddr=True)\
                .function_address
        except AttributeError:
            func_addr = None

        return func_addr

