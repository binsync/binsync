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
from typing import Dict

import idc
import idaapi
import idautils
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_struct
import ida_idaapi

from binsync.data import Struct
from .controller import BinsyncController


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


@execute_read
def get_func_name(ea):
    return idc.get_func_name(ea)


@execute_read
def get_screen_ea():
    return idc.get_screen_ea()


@execute_write
def set_ida_func_name(func_addr, new_name):
    idaapi.set_name(func_addr, new_name, idaapi.SN_FORCE)
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STKVIEW)


@execute_write
def set_ida_comment(addr, cmt, rpt, func_cmt=False):
    if func_cmt:
        print(f"SETTING FUNC COMMENT: '{cmt}'")
        idc.set_func_cmt(addr, cmt, rpt)
    else:
        ida_bytes.set_cmt(addr, cmt, rpt)


@execute_write
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


@execute_write
def set_decomp_comments(func_addr, cmt_dict: Dict[int, str]):
    print(f"setting: {cmt_dict}")

    for addr in cmt_dict:
        ida_cmts = ida_hexrays.user_cmts_new()

        comment = cmt_dict[addr]
        tl = ida_hexrays.treeloc_t()
        tl.ea = addr
        # XXX: need a real value here at some point
        tl.itp = 90
        ida_cmts.insert(tl, ida_hexrays.citem_cmt_t(comment))

        ida_hexrays.save_user_cmts(func_addr, ida_cmts)


@execute_read
def ida_func_addr(addr):
    ida_func = ida_funcs.get_func(addr)
    func_addr = ida_func.start_ea
    return func_addr


@execute_write
def update_struct(struct: Struct, controller: BinsyncController):
    # first, delete any struct by the same name if it exists
    sid = ida_struct.get_struc_id(struct.name)
    if sid != 0xffffffffffffffff:
        sptr = ida_struct.get_struc(sid)
        ida_struct.del_struc(sptr)

    # now make a struct header
    ida_struct.add_struc(ida_idaapi.BADADDR, struct.name, False)
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)

    # expand the struct to the desired size
    ida_struct.expand_struc(sptr, 0, struct.size)

    # add every member of the struct
    for member in struct.struct_members:
        # convert to ida's flag system
        mflag = convert_member_flag(member.size)

        # create the new member
        # TODO: support real types for members
        ida_struct.add_struc_member(
            sptr,
            member.member_name,
            member.offset,
            mflag,
            None,
            member.size,
        )


def parse_struct_type(s_name):
    """
    Utility function to parse the struct name returned by IDA to determine
    if the structure is an actual Struct (user-made) or is a stack variable
    that is located in the stack struct of a function.

    @param s_name:
    @return:
    """
    # its a stack variable
    if "$ F" in s_name:
        func_addr = int(s_name.split("$ F")[1], 16)
        return func_addr
    # it's a real struct
    else:
        return s_name


def convert_member_flag(size):
    if size == 1:
        return 0x400
    elif size == 2:
        return 0x10000400
    elif size == 4:
        return 0x20000400
    elif size == 8:
        return 0x30000400
