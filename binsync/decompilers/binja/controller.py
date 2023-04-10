# ----------------------------------------------------------------------------
# This file contains the BinSyncController class which acts as the the
# bridge between the plugin UI and direct calls to the binsync client found in
# the core of binsync. In the controller, you will find code used to make
# pushes and pulls of user changes.
#
# You will also notice that the BinSyncController runs two extra threads in
# it:
#   1. BinSync "git pulling" thread to constantly get changes from others
#   2. Command Routine to get hooked changes to IDA attributes
#
# The second point is more complicated because it acts as the queue of
# runnable actions that are queued from inside the hooks.py file.
# Essentially, every change that happens in IDA from the main user triggers
# a hook which will push an action to be preformed onto the command queue;
# Causing a "git push" on every change.
#
# ----------------------------------------------------------------------------

import threading
import functools
from typing import Dict, Tuple, Optional, Iterable, Any
import hashlib
import logging

from binaryninja import SymbolType
from binaryninjaui import (
    UIContext,
    DockContextHandler,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja.enums import VariableSourceType
from binaryninja.types import StructureType, EnumerationType

from binsync.api.controller import BSController, fill_event, init_checker
from binsync.data import (
    State, Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct
)
import binsync

from .artifact_lifter import BinjaArtifactLifter
from .compat import bn_enum_to_bs, bn_func_to_bs, bn_struct_to_bs


l = logging.getLogger(__name__)

#
# Helpers
#


def background_and_wait(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        output = [None]

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        thread = threading.Thread(target=thunk)
        thread.start()
        thread.join()

        return output[0]
    return wrapper


#
# Controller
#

class BinjaBSController(BSController):
    def __init__(self, bv=None):
        super(BinjaBSController, self).__init__(artifact_lifter=BinjaArtifactLifter(self))
        self.bv: binaryninja.BinaryView = bv

    def binary_hash(self) -> str:
        hash_ = ""
        try:
            hash_ = hashlib.md5(self.bv.file.raw[:]).hexdigest()
        except Exception:
            pass

        return hash_

    def active_context(self):
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            return None

        ctx = all_contexts[0]
        handler = ctx.contentActionHandler()
        if handler is None:
            return None

        actionContext = handler.actionContext()
        func = actionContext.function
        if func is None:
            return None

        return binsync.data.Function(
            func.start, 0, header=FunctionHeader(func.name, func.start)
        )

    def binary_path(self) -> Optional[str]:
        try:
            return self.bv.file.filename
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        func = self.bv.get_function_at(func_addr)
        if not func:
            return 0

        return func.highest_address - func.start

    def goto_address(self, func_addr) -> None:
        self.bv.offset = func_addr

    #
    # Fillers
    #

    @fill_event
    def fill_struct(self, struct_name, header=True, members=True, artifact=None, **kwargs):
        bs_struct: Struct = artifact
        if not bs_struct:
            l.warning(f"Unable to find the struct: {struct_name} in requested user.")
            return False

        if header:
            self.bv.define_user_type(struct_name, binaryninja.Type.structure())

        if members:
            # this scope assumes that the type is now defined... if it's not we will error
            with binaryninja.Type.builder(self.bv, struct_name) as s:
                s.width = bs_struct.size
                members = list()
                for offset in sorted(bs_struct.members.keys()):
                    bs_memb = bs_struct.members[offset]
                    try:
                        bn_type = self.bv.parse_type_string(bs_memb.type) if bs_memb.type else None
                    except Exception:
                        bn_type = None
                    finally:
                        if bn_type is None:
                            bn_type = binaryninja.Type.int(bs_memb.size)

                    members.append((bn_type, bs_memb.name))

                s.members = members

        return True

    @fill_event
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        changed = False
        bs_global_var: GlobalVariable = artifact
        bn_global_var: binaryninja.DataVariable = self.bv.get_data_var_at(var_addr)
        global_type = self.bv.parse_type_string(bs_global_var.type)
        
        if bs_global_var and bs_global_var.name:
            if bn_global_var is None:
                bn_global_var = self.bv.define_user_data_var(bs_global_var.addr, global_type, bs_global_var.name)
                changed = True
        
            if bn_global_var.name != bs_global_var.name or bn_global_var.type != global_type:
                bn_global_var = self.bv.define_user_data_var(bs_global_var.addr, global_type, bs_global_var.name)
                changed = True

        return changed

    @background_and_wait
    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        """
        Grab all relevant information from the specified user and fill the @bn_func.
        """
        bs_func: Function = artifact
        bn_func = self.bv.get_function_at(bs_func.addr)

        changes = super(BinjaBSController, self).fill_function(
            func_addr, user=user, artifact=artifact, bn_func=bn_func, **kwargs
        )
        bn_func.reanalyze()
        return changes

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, bn_func=None, **kwargs):
        updates = False
        bs_func_header: FunctionHeader = artifact

        if bs_func_header:
            # func name
            if bs_func_header.name and bs_func_header.name != bn_func.name:
                bn_func.name = bs_func_header.name
                updates |= True

            # ret type
            if bs_func_header.type and \
                    bs_func_header.type != bn_func.return_type.get_string_before_name():

                valid_type = False
                try:
                    new_type, _ = self.bv.parse_type_string(bs_func_header.type)
                    valid_type = True
                except Exception:
                    pass

                if valid_type:
                    bn_func.return_type = new_type
                    updates |= True

            # parameters
            if bs_func_header.args:
                prototype_tokens = [bs_func_header.type] if bs_func_header.type \
                    else [bn_func.return_type.get_string_before_name()]

                prototype_tokens.append("(")
                for idx, func_arg in bs_func_header.args.items():
                    prototype_tokens.append(func_arg.type)
                    prototype_tokens.append(func_arg.name)
                    prototype_tokens.append(",")

                if prototype_tokens[-1] == ",":
                    prototype_tokens[-1] = ")"

                prototype_str = " ".join(prototype_tokens)

                valid_type = False
                try:
                    bn_prototype, _ = self.bv.parse_type_string(prototype_str)
                    valid_type = True
                except Exception:
                    pass

                if valid_type:
                    bn_func.type = bn_prototype
                    updates |= True

        return updates

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, bn_func=None, **kwargs):
        updates = False
        bs_stack_var: StackVariable = artifact

        existing_stack_vars: Dict[int, Any] = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType
        }

        bn_offset = bs_stack_var.offset
        if bn_offset in existing_stack_vars:
            if existing_stack_vars[bn_offset].name != bs_stack_var.name:
                existing_stack_vars[bn_offset].name = bs_stack_var.name

            valid_type = False
            try:
                type_, _ = self.bv.parse_type_string(bs_stack_var.type)
                valid_type = True
            except Exception:
                pass

            if valid_type:
                if existing_stack_vars[bn_offset].type != type_:
                    existing_stack_vars[bn_offset].type = type_
                try:
                    bn_func.create_user_stack_var(bn_offset, type_, bs_stack_var.name)
                    bn_func.create_auto_stack_var(bn_offset, type_, bs_stack_var.name)
                except Exception as e:
                    l.warning(f"BinSync could not sync stack variable at offset {bn_offset}: {e}")

                updates |= True

        return updates

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, bn_func=None, **kwargs):
        # TODO: check if the comment changed when set!
        comment: Comment = artifact
        bn_func.set_comment_at(comment.addr, comment.comment)

        return True
    
    @fill_event
    def fill_enum(self, name, user=None, artifact=None, ida_code_view=None, **kwargs):
        bs_enum: Enum = artifact
        bn_enum: binaryninja.EnumerationType = self.bv.types.get(name)
        
        bn_members = []
        
        for member_name, value in bs_enum.members.items():
            bn_members.append({ "name": member_name, "value": value })
        
        new_type = binaryninja.TypeBuilder.enumeration(self.bv.arch, bn_members)
        
        self.bv.define_user_type(name, new_type)
            
        return True

    #
    # Artifact API
    #

    def function(self, addr, **kwargs) -> Optional[Function]:
        bn_func = self.bv.get_function_at(addr)
        if not bn_func:
            return None

        return bn_func_to_bs(bn_func)

    def functions(self) -> Dict[int, Function]:
        funcs = {}
        for bn_func in self.bv.functions:
            if bn_func.symbol.type != SymbolType.FunctionSymbol:
                continue

            funcs[bn_func.start] = Function(bn_func.start, bn_func.total_bytes)
            funcs[bn_func.start].name = bn_func.name

        return funcs
    

    def enum(self, name) -> Optional[Enum]:
        bn_enum = self.bv.types.get(name, None)
        if bn_enum is None:
            return None
        
        if isinstance(bn_enum, EnumerationType):
            return bn_enum_to_bs(name, bn_enum)
        
        return None
    
    def enums(self) -> Dict[str, Enum]:                        
        return {
            name: bn_enum_to_bs(''.join(name.name), t) for name, t in self.bv.types.items()
            if isinstance(t, EnumerationType)
        }

    def struct(self, name) -> Optional[Struct]:
        bn_struct = self.bv.types.get(name, None)
        if bn_struct is None or not isinstance(bn_struct, StructureType):
            return None

        return bn_struct_to_bs(name, bn_struct)

    def structs(self) -> Dict[str, Struct]:
        return {
            name: Struct(''.join(name.name), t.width, {}) for name, t in self.bv.types.items()
            if isinstance(t, StructureType)
        }

    def global_vars(self) -> Dict[int, GlobalVariable]:
        return {
            addr: GlobalVariable(addr, var.name or f"data_{addr:x}")
            for addr, var in self.bv.data_vars.items()
        }
    
    def global_var(self, addr) -> Optional[GlobalVariable]:
        try:
            var = self.bv.data_vars[addr]
        except KeyError:
            return None 
            
        gvar = GlobalVariable(
            addr, self.bv.get_symbol_at(addr) or f"data_{addr:x}", type_=str(var.type) if var.type is not None else None, size=var.type.width
        )
        return gvar
