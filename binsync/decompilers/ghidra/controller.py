from typing import Optional, Dict, List, Tuple
import logging
from functools import wraps

from binsync.api.controller import BSController, init_checker, fill_event
from binsync.data import (
    Function, FunctionHeader, StackVariable, Comment, FunctionArgument, GlobalVariable
)

from .artifact_lifter import GhidraArtifactLifter
from .ghidra_api import GhidraAPIWrapper

l = logging.getLogger(__name__)


def ghidra_transaction(f):
    @wraps(f)
    def _ghidra_transaction(self, *args, **kwargs):
        op_name = str(f.__qualname__)
        trans_id = self.ghidra.currentProgram.startTransaction(op_name)
        ret_val = None
        try:
            ret_val = f(self, *args, **kwargs)
        except Exception as e:
            l.warning(f"Failed to do Ghidra Transaction {op_name} because {e}")
        finally:
            self.ghidra.currentProgram.endTransaction(trans_id, True)

        return ret_val

    return _ghidra_transaction


class GhidraBSController(BSController):
    def __init__(self, **kwargs):
        self.ghidra: Optional[GhidraAPIWrapper] = None
        super(GhidraBSController, self).__init__(GhidraArtifactLifter(self), **kwargs)

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
        self.ghidra.goTo(self.ghidra.toAddr(func_addr))

    def connect_ghidra_bridge(self):
        self.ghidra = GhidraAPIWrapper(self)
        return self.ghidra.connected

    #
    # Filler/Setter API
    #

    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        decompilation = self._ghidra_decompile(self._get_nearest_function(func_addr))
        changes = super(GhidraBSController, self).fill_function(
            func_addr, user=user, artifact=artifact, decompilation=decompilation, **kwargs
        )

        return changes

    @fill_event
    @ghidra_transaction
    def fill_function_header(self, func_addr, user=None, artifact=None, decompilation=None, **kwargs):
        changes = False
        func_header: FunctionHeader = artifact
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")

        # func name
        if func_header.name and func_header.name != ghidra_func.getName():
            ghidra_func.setName(func_header.name, src_type.USER_DEFINED)
            changes = True

        # return type
        if func_header.type and decompilation is not None:
            parsed_type = self.typestr_to_gtype(func_header.type)
            if parsed_type is not None and \
                    parsed_type != str(decompilation.highFunction.getFunctionPrototype().getReturnType()):
                ghidra_func.setReturnType(parsed_type, src_type.USER_DEFINED)
                changes = True

        # args
        if func_header.args and decompilation is not None:
            # TODO: do arg names and types
            pass

        return changes

    @fill_event
    @ghidra_transaction
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, decompilation=None, **kwargs):
        stack_var: StackVariable = artifact
        changes = False
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)
        gstack_var = self._get_gstack_var(ghidra_func, offset)
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")

        if stack_var.name and stack_var.name != gstack_var.getName():
            gstack_var.setName(stack_var.name, src_type.USER_DEFINED)
            changes = True

        if stack_var.type:
            parsed_type = self.typestr_to_gtype(stack_var.type)
            if parsed_type is not None and parsed_type != str(gstack_var.getDataType()):
                gstack_var.setDataType(parsed_type, False, True, src_type.USER_DEFINED)
                changes = True

        return changes

    @fill_event
    @ghidra_transaction
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        changes = False
        global_var: GlobalVariable = artifact
        all_global_vars = self.global_vars()

        rename_label_cmd_cls = self.ghidra.import_module_object("ghidra.app.cmd.label", "RenameLabelCmd")
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")
        for offset, gvar in all_global_vars.items():
            if offset != var_addr:
                continue

            if global_var.name and global_var.name != gvar.name:
                sym = self.ghidra.getSymbolAt(self.ghidra.toAddr(var_addr))
                cmd = rename_label_cmd_cls(sym, global_var.name, src_type.USER_DEFINED)
                cmd.applyTo(self.ghidra.currentProgram)
                changes = True

            if global_var.type:
                # TODO: set type
                pass

            break

        return changes

    @fill_event
    @ghidra_transaction
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        comment: Comment = artifact
        code_unit = self.ghidra.import_module_object("ghidra.program.model.listing", "CodeUnit")
        set_cmt_cmd_cls = self.ghidra.import_module_object("ghidra.app.cmd.comments", "SetCommentCmd")
        cmt_type = code_unit.PRE_COMMENT if comment.decompiled else code_unit.EOL_COMMENT

        if comment.comment:
            # TODO: check if comment already exists, and append?
            return set_cmt_cmd_cls(
                self.ghidra.toAddr(addr), cmt_type, comment.comment
            ).applyTo(self.ghidra.currentProgram)

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
        func = self._get_nearest_function(addr)
        dec = self._ghidra_decompile(func)
        # optimize on remote
        # TODO: Figure out why only some stack variables get pushed
        stack_variable_info: Optional[List[Tuple[int, str, str, int]]] = self.ghidra.bridge.remote_eval(
            "[(sym.getStorage().getStackOffset(), sym.getName(), str(sym.getDataType()), sym.getSize()) "
            "for sym in dec.getHighFunction().getLocalSymbolMap().getSymbols() "
            "if sym.getStorage().isStackStorage()]",
            dec=dec
        )
        stack_variables = {}
        if stack_variable_info:
            stack_variables = {
                offset: StackVariable(offset, name, typestr, size, addr) for offset, name, typestr, size in stack_variable_info
            }

        bs_func = Function(
            func.getEntryPoint().getOffset(), func.getBody().getNumAddresses(),
            header=FunctionHeader(func.getName(), func.getEntryPoint().getOffset()),
            stack_vars=stack_variables
        )
        return bs_func

    def functions(self) -> Dict[int, Function]:
        # optimization to speed up remote evaluation
        name_and_sizes: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(f.getName(), f.getEntryPoint().getOffset()) "
            "for f in currentProgram.getFunctionManager().getFunctions(True)]"
        )
        if name_and_sizes is None:
            l.warning(f"Failed to get any functions from Ghidra. Did something break?")
            return {}

        funcs = {
            addr: Function(addr, 0, header=FunctionHeader(name, addr)) for name, addr in name_and_sizes
        }
        return funcs

    def global_var(self, addr) -> Optional[GlobalVariable]:
        light_global_vars = self.global_vars()
        for offset, global_var in light_global_vars.items():
            if offset == addr:
                lst = self.ghidra.currentProgram.getListing()
                # TODO: Fix error with getDataAt() from ghidra bridge
                data = lst.getDataAt(addr)
                if not data or data.isStructure():
                    return None
                if str(data.getDataType()) == "undefined":
                    size = self.ghidra.currentProgram.getDefaultPointerSize()
                else:
                    size = data.getLength()

                global_var.size = size
                return global_var

    def global_vars(self) -> Dict[int, GlobalVariable]:
        symbol_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SymbolType")
        symbol_table = self.ghidra.currentProgram.getSymbolTable()
        # optimize by grabbing all symbols at once
        gvar_addr_and_name: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(sym.getName(), sym.getAddress().getOffset()) "
            "for sym in symbol_table.getAllSymbols(True) "
            "if sym.getSymbolType() == symbol_type.LABEL]",
            symbol_type=symbol_type, symbol_table=symbol_table
        )
        gvars = {
            addr: GlobalVariable(addr, name) for name, addr in gvar_addr_and_name
        }
        return gvars

    def stack_variable(self, func_addr, offset) -> Optional[StackVariable]:
        gstack_var = self._get_gstack_var(func_addr, offset)

        if gstack_var is None:
            return None
        bs_stack_var = self._gstack_var_to_bsvar(gstack_var)
        return bs_stack_var


    #
    # Ghidra Specific API
    #

    def _get_nearest_function(self, addr: int) -> "GhidraFunction":
        func_manager = self.ghidra.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self.ghidra.toAddr(addr))

    def _gstack_var_to_bsvar(self, gstack_var: "LocalVariableDB"):
        if gstack_var is None:
            return None

        bs_stack_var = StackVariable(
            gstack_var.getStackOffset(),
            gstack_var.getName(),
            str(gstack_var.getDataType()),
            gstack_var.getLength(),
            gstack_var.getFunction().getEntryPoint().getOffset() # Unsure if this is what is wanted here
        )
        return bs_stack_var

    def _gfunc_to_bsfunc(self, gfunc: "GhidraFunction"):
        if gfunc is None:
            return None

        bs_func = Function(
            gfunc.getEntryPoint().getOffset(), gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(gfunc.getName(), gfunc.getEntryPoint().getOffset()),
        )
        return bs_func

    def _ghidra_decompile(self, func: "GhidraFunction") -> "DecompileResult":
        """
        TODO: this needs to be cached!
        @param func:
        @return:
        """
        dec_interface_cls = self.ghidra.import_module_object("ghidra.app.decompiler", "DecompInterface")
        consle_monitor_cls = self.ghidra.import_module_object("ghidra.util.task", "ConsoleTaskMonitor")

        dec_interface = dec_interface_cls()
        dec_interface.openProgram(self.ghidra.currentProgram)
        dec_results = dec_interface.decompileFunction(func, 0, consle_monitor_cls())
        return dec_results

    def _get_gstack_var(self, func: "GhidraFunction", offset: int) -> Optional["LocalVariableDB"]:
        """
        @param func:
        @param offset:
        @return:
        """
        for var in func.getAllVariables():
            if not var.isStackVariable():
                continue

            if var.getStackOffset() == offset:
                return var

        return None

    def typestr_to_gtype(self, typestr: str) -> Optional["DataType"]:
        """
        typestr should look something like:
        `int` or if a struct `struct name`.

        @param typestr:
        @return:
        """
        if not typestr:
            return None

        dtm_service_class = self.ghidra.import_module_object("ghidra.app.services", "DataTypeManagerService")
        dtp_class = self.ghidra.import_module_object("ghidra.util.data", "DataTypeParser")
        dt_service = self.ghidra.getState().getTool().getService(dtm_service_class)
        dt_parser = dtp_class(dt_service, dtp_class.AllowedDataTypes.ALL)
        try:
            parsed_type = dt_parser.parse(typestr)
        except Exception as e:
            l.warning(f"Failed to parse type string: {typestr}")
            return None

        return parsed_type

    def prototype_str_to_gtype(self, progotype_str: str) -> Optional["FunctionDefinitionDataType"]:
        """
        Strings must look like:
        'void functions1(int p1, int p2)'
        """
        if not progotype_str:
            return None

        c_parser_utils_cls = self.ghidra.import_module_object("ghidra.app.util.cparser.C", "CParserUtils")
        program = self.ghidra.currentProgram
        return c_parser_utils_cls.parseSignature(program, progotype_str)
