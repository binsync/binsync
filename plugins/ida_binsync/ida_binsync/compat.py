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

import idc
import idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_struct
import ida_idaapi
import ida_typeinf

from binsync.data import Struct
from .controller import BinsyncController


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
    func_addr = ida_func.start_ea
    return func_addr


@execute_read
def get_func_name(ea):
    return idc.get_func_name(ea)


@execute_write
def set_ida_func_name(func_addr, new_name):
    idaapi.set_name(func_addr, new_name, idaapi.SN_FORCE)
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STKVIEW)


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
    decompilation = ida_hexrays.decompile(func_addr)
    stack_var_info = {}

    for var in decompilation.lvars:
        if not var.is_stk_var():
            continue

        size = var.width
        name = var.name
        offset = var.location.stkoff()
        type_str = str(var.type())
        stack_var_info[offset] = IDAStackVar(func_addr, offset, name, type_str, size)

    return stack_var_info


@execute_write
def set_stack_vars_types(var_type_dict, code_view, controller: "BinsyncController") -> bool:
    """
    Sets the type of a stack variable, which should be a local variable.
    Take special note of the types of first two parameters used here:
    var_type_dict is a dictionary of the offsets and the new proposed type info for each offset.
    This typeinfo should be gotten either by manully making a new typeinfo object or using the
    parse_decl function. code_view is a instance of vdui_t, which should be gotten through
    open_pseudocode() from ida_hexrays.

    This function also is special since it needs to iterate all of the stack variables an unknown amount
    of times until a fixed point of variables types not changing is met.


    @param var_type_dict:       Dict[stack_offset, ida_typeinf_t]
    @param code_view:           A pointer to a vdui_t screen
    @param controller:          The BinSync controller to do operations on
    @return:
    """

    all_success = True
    fixed_point = False
    while not fixed_point:
        fixed_point = True
        for lvar in code_view.cfunc.lvars:
            cur_off = lvar.location.stkoff()
            if lvar.is_stk_var() and cur_off in var_type_dict:
                controller.inc_api_count()
                all_success &= code_view.set_lvar_type(lvar, var_type_dict.pop(cur_off))
                fixed_point = False
                # make sure to break, in case the size of lvars array has now changed
                break

    return all_success

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
    # first, delete any struct by the same name if it exists
    sid = ida_struct.get_struc_id(struct.name)
    if sid != 0xffffffffffffffff:
        sptr = ida_struct.get_struc(sid)
        controller.inc_api_count()
        ida_struct.del_struc(sptr)

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
        ida_struct.add_struc_member(
            sptr,
            member.member_name,
            member.offset,
            mflag,
            None,
            member.size,
        )


@execute_write
def set_ida_struct_member_types(struct: Struct, controller) -> bool:
    # find the specific struct
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)
    all_typed_success = True

    for idx, member in enumerate(struct.struct_members):
        # set the new member type if it has one
        if member.type == "":
            continue

        # assure its convertible
        tif = convert_type_str_to_ida_type(member.type)
        if tif is None:
            all_typed_success = False
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
        all_typed_success &= True if was_set == 1 else False

    return all_typed_success


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


def get_function_cursor_at():
    curr_addr = get_screen_ea()
    if curr_addr is None:
        return None

    return ida_func_addr(curr_addr)

