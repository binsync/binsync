import functools
import threading

import idc
import idaapi
import idautils
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_bytes

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
def set_ida_comment(addr, cmt, rpt, func_cmt=False):
    if func_cmt:
        print(f"SETTING FUNC COMMENT: '{cmt}'")
        idc.set_func_cmt(addr, cmt, rpt)
    else:
        ida_bytes.set_cmt(addr, cmt, rpt)
