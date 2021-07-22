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
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_struct
import ida_idaapi
import ida_typeinf

from binsync.data import Struct

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


#
#   IDA Stack Var r/w
#

@execute_write
def set_stack_var_type(func_addr, ida_stack_var_offset, ida_type):
    """
    Sets a stack variable's type in the GUI and IDB

    @param func_addr:
    @param ida_stack_var_offset:
    @param ida_type:
    @return:
    """

    # Modification to local variables in IDA must be done through ida_hexrays.modify_user_lvars
    # which requires the use of a user_lvar_modifier_t object. The custom class must also implement
    # the modify_lvars function which will be responsible for deciding how to modify the lvars present
    # at the address the modifier is used on. For function addresses, this will get you the local stack
    # variables. You will get all the stack variables, so you must search for the right one to modify.
    class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
        def __init__(self, stack_off, new_type):
            ida_hexrays.user_lvar_modifier_t.__init__(self)
            self.stack_off = stack_off
            self.new_type = new_type

        def modify_lvars(self, lvars):
            for curr_var in lvars.lvvec:
                if curr_var.ll.is_stk_var() and curr_var.ll.get_stkoff() == self.stack_off:
                    curr_var.type = self.new_type
                    return True

            return False

    mods = my_modifier_t(ida_stack_var_offset, ida_type)
    ida_hexrays.modify_user_lvars(func_addr, mods)



#
#   IDA Struct r/w
#

@execute_write
def update_struct(struct: Struct, controller):
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


#
#   IDA GUI r/w
#

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


@execute_read
def get_screen_ea():
    return idc.get_screen_ea()


#
#   Data Type Converters
#

def convert_type_str_to_ida_type(type_str):
    ida_type_str = type_str + ";"
    tif = ida_typeinf.tinfo_t()
    valid_parse = ida_typeinf.parse_decl(tif, None, ida_type_str, 1)

    return tif if valid_parse is not None else None


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
