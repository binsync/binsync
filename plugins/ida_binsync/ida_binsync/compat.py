# ----------------------------------------------------------------------------
# This file is more of a library for making compatibility calls to IDA for
# things such as getting decompiled function names, start addresses, and
# asking for write permission to ida. This will mostly be called in the
# controller.
#
# Note that anything that requires write permission to IDA will need to pass
# through this program if it is not running in the main thread.
#
# ----------------------------------------------------------------------------

import functools
import threading
import typing
import logging

import idc
import idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_struct
import ida_idaapi
import ida_typeinf

import binsync
from binsync.data import Struct
from .controller import IDABinSyncController

l = logging.getLogger(__name__)

#
#   Helper classes for wrapping data
#


class IDAStackVar:
    def __init__(self, func_addr, offset, name, type_str, size):
        self.func_addr = func_addr
        self.offset = offset
        self.name = name
        self.type_str = type_str
        self.size = size


class IDAFunctionArg:
    def __init__(self, idx, name, type_str, size):
        self.idx = idx
        self.name = name
        self.type_str = type_str
        self.size = size


class IDAFunction:
    def __init__(self, func_addr, name, ret_type_str, func_args: typing.Dict[int, IDAFunctionArg]):
        self.func_addr = func_addr
        self.name = name
        self.ret_type_str = ret_type_str
        self.func_args = func_args


#
#   Wrappers for IDA Main thread r/w operations
#

# a special note about these functions:
# Any operation that needs to do some type of write to the ida db (idb), needs to be in the main thread due to
# some ida constraints. Sometimes reads also need to be in the main thread. To make things efficient, most heavy
# things are done in the controller and just setters and getters are done here.


def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)


def execute_sync(func, sync_type):
    """
    Synchronize with the disassembler for safe database access.
    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper


def execute_read(func):
    return execute_sync(func, idaapi.MFF_READ)


def execute_write(func):
    return execute_sync(func, idaapi.MFF_WRITE)


def execute_ui(func):
    return execute_sync(func, idaapi.MFF_FAST)


#
#   Data Type Converters
#
@execute_read
def convert_type_str_to_ida_type(type_str) -> typing.Optional['ida_typeinf']:
    ida_type_str = type_str + ";"
    tif = ida_typeinf.tinfo_t()
    valid_parse = ida_typeinf.parse_decl(tif, None, ida_type_str, 1)

    return tif if valid_parse is not None else None

@execute_read
def ida_to_angr_stack_offset(func_addr, angr_stack_offset):
    frame = idaapi.get_frame(func_addr)
    frame_size = idc.get_struc_size(frame)
    last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))
    ida_stack_offset = angr_stack_offset - frame_size + last_member_size
    return ida_stack_offset


def convert_member_flag(size):
    if size == 1:
        return 0x400
    elif size == 2:
        return 0x10000400
    elif size == 4:
        return 0x20000400
    elif size == 8:
        return 0x30000400


#
#   IDA Function r/w
#

@execute_read
def ida_func_addr(addr):
    ida_func = ida_funcs.get_func(addr)
    if ida_func is None:
        return None

    func_addr = ida_func.start_ea
    return func_addr


@execute_read
def get_func_name(ea) -> typing.Optional[str]:
    return idc.get_func_name(ea)


@execute_read
def get_func_size(ea):
    func = idaapi.get_func(ea)
    if not func:
        return 0

    return func.size()


@execute_write
def set_ida_func_name(func_addr, new_name):
    idaapi.set_name(func_addr, new_name, idaapi.SN_FORCE)
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STKVIEW)


@execute_read
def get_func_header_info(ida_cfunc) -> IDAFunction:
    func_addr = ida_cfunc.entry_ea

    # collect the function arguments
    func_args = {}
    for idx, arg in enumerate(ida_cfunc.arguments):
        size = arg.width
        name = arg.name
        type_str = str(arg.type())
        func_args[idx] = IDAFunctionArg(idx, name, type_str, size)

    # collect the header ret_type and name
    func_name = get_func_name(func_addr)
    try:
        ret_type_str = str(ida_cfunc.type.get_rettype())
    except Exception:
        ret_type_str = ""

    ida_function_info = IDAFunction(func_addr, func_name, ret_type_str, func_args)
    return ida_function_info


@execute_write
def set_func_header(ida_func_code_view, binsync_header: binsync.data.FunctionHeader,
                    controller, exit_on_bad_type=False):
    data_changed = False
    ida_cfunc = ida_func_code_view.cfunc
    func_addr = ida_cfunc.entry_ea

    cur_ida_func = get_func_header_info(ida_cfunc)

    #
    # FUNCTION NAME
    #

    if binsync_header.name and binsync_header.name != cur_ida_func.name:
        controller.inc_api_count()
        set_ida_func_name(func_addr, binsync_header.name)

    #
    # FUNCTION RET TYPE
    #

    func_name = get_func_name(func_addr)
    cur_ret_type_str = str(ida_cfunc.type.get_rettype())
    if binsync_header.ret_type and binsync_header.ret_type != cur_ret_type_str:
        old_prototype = str(ida_cfunc.type).replace("(", f" {func_name}(", 1)
        new_prototype = old_prototype.replace(cur_ret_type_str, binsync_header.ret_type, 1)
        controller.inc_api_count()
        success = idc.SetType(func_addr, new_prototype)

        # we may need to reload types
        if success is None and exit_on_bad_type:
            return None

        data_changed |= success is True
        refresh_pseudocode_view(func_addr)

    #
    # FUNCTION ARGS
    #

    types_to_change = {}
    for idx, binsync_arg in binsync_header.args.items():
        if idx >= len(cur_ida_func.func_args):
            break

        cur_ida_arg = cur_ida_func.func_args[idx]

        # change the name
        if binsync_arg.name and binsync_arg.name != cur_ida_arg.name:
            controller.inc_api_count()
            success = ida_func_code_view.rename_lvar(ida_cfunc.arguments[idx], binsync_arg.name, 1)
            data_changed |= success is True
            refresh_pseudocode_view(func_addr)

        # record the type to change
        if binsync_arg.type_str and binsync_arg.type_str != cur_ida_arg.type_str:
            types_to_change[idx] = (cur_ida_arg.type_str, binsync_arg.type_str)

    # crazy prototype parsing
    func_prototype = str(ida_cfunc.type).replace("(", f" {func_name}(", 1)
    proto_split = func_prototype.split("(", maxsplit=1)
    proto_head, proto_body = proto_split[0], "(" + proto_split[1]
    arg_strs = proto_body.split(",")

    # update prototype body from left to right
    for idx in range(len(cur_ida_func.func_args)):
        try:
            old_t, new_t = types_to_change[idx]
        except KeyError:
            continue

        arg_strs[idx] = arg_strs[idx].replace(old_t, new_t, 1)

    # set the change
    proto_body = ",".join(arg_strs)
    new_prototype = proto_head + proto_body
    controller.inc_api_count()
    success = idc.SetType(func_addr, new_prototype)

    # we may need to reload types
    if success is None and exit_on_bad_type:
        return None

    data_changed |= success is True

    return data_changed


#
#   IDA Comment r/w
#

@execute_write
def set_ida_comment(addr, cmt, decompiled=False):
    func = ida_funcs.get_func(addr)
    rpt = 1

    # function comment
    if addr == func.start_ea:
        idc.set_func_cmt(addr, cmt, rpt)
        return True

    # a comment in decompilation
    elif decompiled:
        cfunc = idaapi.decompile(addr)
        eamap = cfunc.get_eamap()
        decomp_obj_addr = eamap[addr][0].ea
        tl = idaapi.treeloc_t()

        # try to set a comment using the cfunc obj and normal address
        for a in [addr, decomp_obj_addr]:
            tl.ea = a
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, cmt)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()

                # attempt to set until it does not fail (orphan itself)
                if not cfunc.has_orphan_cmts():
                    cfunc.save_user_cmts()
                    return True
                cfunc.del_orphan_cmts()

        return False

    # a comment in disassembly
    else:
        ida_bytes.set_cmt(addr, cmt, rpt)
        return True


@execute_write
def set_decomp_comments(func_addr, cmt_dict: typing.Dict[int, str]):
    for addr in cmt_dict:
        ida_cmts = ida_hexrays.user_cmts_new()

        comment = cmt_dict[addr]
        tl = ida_hexrays.treeloc_t()
        tl.ea = addr
        # XXX: need a real value here at some point
        tl.itp = 90
        ida_cmts.insert(tl, ida_hexrays.citem_cmt_t(comment))

        ida_hexrays.save_user_cmts(func_addr, ida_cmts)


#
#   IDA Stack Var r/w
#

@execute_read
def get_func_stack_var_info(func_addr) -> typing.Dict[int, IDAStackVar]:
    try:
        decompilation = ida_hexrays.decompile(func_addr)
    except ida_hexrays.DecompilationFailure:
        print("[BinSync]: Decompiling too many functions too fast! Slow down and try that operation again.")
        return {}

    stack_var_info = {}

    for var in decompilation.lvars:
        if not var.is_stk_var():
            continue

        size = var.width
        name = var.name
        offset = var.location.stkoff() - decompilation.get_stkoff_delta()
        type_str = str(var.type())
        stack_var_info[offset] = IDAStackVar(func_addr, offset, name, type_str, size)

    return stack_var_info


@execute_write
def set_stack_vars_types(var_type_dict, code_view, controller: "IDABinSyncController") -> bool:
    """
    Sets the type of a stack variable, which should be a local variable.
    Take special note of the types of first two parameters used here:
    var_type_dict is a dictionary of the offsets and the new proposed type info for each offset.
    This typeinfo should be gotten either by manully making a new typeinfo object or using the
    parse_decl function. code_view is a _instance of vdui_t, which should be gotten through
    open_pseudocode() from ida_hexrays.

    This function also is special since it needs to iterate all of the stack variables an unknown amount
    of times until a fixed point of variables types not changing is met.


    @param var_type_dict:       Dict[stack_offset, ida_typeinf_t]
    @param code_view:           A pointer to a vdui_t screen
    @param controller:          The BinSync controller to do operations on
    @return:
    """

    data_changed = False
    fixed_point = False
    while not fixed_point:
        fixed_point = True
        for lvar in code_view.cfunc.lvars:
            cur_off = lvar.location.stkoff() - code_view.cfunc.get_stkoff_delta()
            if lvar.is_stk_var() and cur_off in var_type_dict:
                if str(lvar.type()) != str(var_type_dict[cur_off]):
                    controller.inc_api_count()
                    data_changed |= code_view.set_lvar_type(lvar, var_type_dict.pop(cur_off))
                    fixed_point = False
                    # make sure to break, in case the size of lvars array has now changed
                    break

    return data_changed

@execute_read
def ida_get_frame(func_addr):
    return idaapi.get_frame(func_addr)


#
#   IDA Struct r/w
#
@execute_write
def set_struct_member_name(ida_struct, frame, offset, name):
    ida_struct.set_member_name(frame, offset, name)

@execute_write
def set_ida_struct(struct: Struct, controller) -> bool:
    data_changed = False

    # first, delete any struct by the same name if it exists
    sid = ida_struct.get_struc_id(struct.name)
    if sid != 0xffffffffffffffff:
        sptr = ida_struct.get_struc(sid)
        controller.inc_api_count()
        data_changed |= ida_struct.del_struc(sptr)

    # now make a struct header
    controller.inc_api_count()
    ida_struct.add_struc(ida_idaapi.BADADDR, struct.name, False)
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)

    # expand the struct to the desired size
    # XXX: do not increment API here, why? Not sure, but you cant do it here.
    ida_struct.expand_struc(sptr, 0, struct.size)

    # add every member of the struct
    for member in struct.struct_members:
        # convert to ida's flag system
        mflag = convert_member_flag(member.size)

        # create the new member
        controller.inc_api_count()
        data_changed |= ida_struct.add_struc_member(
            sptr,
            member.member_name,
            member.offset,
            mflag,
            None,
            member.size,
        )

    return data_changed


@execute_write
def set_ida_struct_member_types(struct: Struct, controller) -> bool:
    # find the specific struct
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)
    data_changed = False

    for idx, member in enumerate(struct.struct_members):
        # set the new member type if it has one
        if member.type == "":
            continue

        # assure its convertible
        tif = convert_type_str_to_ida_type(member.type)
        if tif is None:
            continue

        # set the type
        mptr = sptr.get_member(idx)
        controller.inc_api_count()
        was_set = ida_struct.set_member_tinfo(
            sptr,
            mptr,
            0,
            tif,
            mptr.flag
        )
        data_changed |= was_set == 1

    return data_changed

#
# Other Globals
#

@execute_write
def set_global_var_name(var_addr, name):
    return idaapi.set_name(var_addr, name)

#
#   IDA GUI r/w
#

@execute_ui
def refresh_pseudocode_view(ea):
    """Refreshes the pseudocode view in IDA."""
    names = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]
    for name in names:
        widget = ida_kernwin.find_widget(name)
        if widget:
            vu = ida_hexrays.get_widget_vdui(widget)

            # Check if the address is in the same function
            func_ea = vu.cfunc.entry_ea
            func = ida_funcs.get_func(func_ea)
            if ida_funcs.func_contains(func, ea):
                vu.refresh_view(True)


class IDAViewCTX:
    @execute_ui
    def __init__(self, func_addr):
        self.view = ida_hexrays.open_pseudocode(func_addr, 0)

    def __enter__(self):
        return self.view

    @execute_ui
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_pseudocode_view(self.view)

    @execute_ui
    def close_pseudocode_view(self, ida_vdui_t):
        widget = ida_vdui_t.toplevel
        idaapi.close_pseudocode(widget)


def get_screen_ea():
    return idc.get_screen_ea()


@execute_read
def get_function_cursor_at():
    curr_addr = get_screen_ea()
    if curr_addr is None:
        return None

    return ida_func_addr(curr_addr)


#
# Other Utils
#

@execute_read
def get_binary_path():
    return idaapi.get_input_file_path()
