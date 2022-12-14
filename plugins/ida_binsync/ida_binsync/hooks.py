# ----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#
# This program describes each hook in IDA that we want to overwrite on the
# startup of IDA. Each hook function/class describes a different scenario
# that we try to track when a user makes a change. For _instance, the function
# `cmt_changed` is activated every time a user changes a disassembly comment,
# allowing us to send the new comment to be queued in the Controller actions.
#
# ----------------------------------------------------------------------------
import threading
import time
from functools import wraps
import logging

import ida_auto
import ida_bytes
import ida_enum
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_netnode
import ida_pro
import ida_segment
import ida_struct
import ida_typeinf
import ida_enum
import idaapi
import idc

from . import compat
from .controller import IDABinSyncController
from binsync.data import (
    Function, FunctionHeader, FunctionArgument, StackVariable, StackOffsetType,
    Comment, GlobalVariable, Patch,
    Enum, Struct
)

l = logging.getLogger(__name__)

#
#   Decorators
#


def quite_init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if not self.controller.check_client():
            return 0
        return f(self, *args, **kwargs)
    return initcheck


def stop_if_syncing(f):
    @wraps(f)
    def _stop_if_syncing(self, *args, **kwargs):
        if self.controller.sync_lock.locked():
            return 0

        return f(self, *args, **kwargs)

    return _stop_if_syncing

#
#   IDA Change Hooks
#


class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self, controller):
        ida_idp.IDB_Hooks.__init__(self)
        self.controller: IDABinSyncController = controller
        self.last_local_type = None

    @quite_init_checker
    @stop_if_syncing
    def local_types_changed(self):
        #print("local type changed")
        return 0

    @quite_init_checker
    @stop_if_syncing
    def ti_changed(self, ea, type_, fname):
        #print(f"TI CHANGED: {ea}, {type_}, {fname}")
        return 0

    #
    #   Enum Hooks
    #

    def bs_enum_modified(self, enum):
        name = ida_enum.get_enum_name(enum)
        _enum = compat.enum(name)
        self.binsync_state_change(
            self.controller.push_artifact,
            _enum
        )

    @quite_init_checker
    @stop_if_syncing
    def enum_created(self, enum):
        self.bs_enum_modified(enum)
        return 0

    # XXX - use enum_deleted(self, id) instead?
    @quite_init_checker
    @stop_if_syncing
    def deleting_enum(self, id):
        name = ida_enum.get_enum_name(id)
        enum = Enum(name, {})
        self.binsync_state_change(
            self.controller.push_artifact,
            enum
        )
        return 0

    # XXX - use enum_renamed(self, id) instead?
    @quite_init_checker
    @stop_if_syncing
    def renaming_enum(self, id, is_enum, newname):
        if is_enum:
            self.bs_enum_modified(id)
        else:
            self.bs_enum_modified(ida_enum.get_enum_member_enum(id))
        return 0

    @quite_init_checker
    @stop_if_syncing
    def enum_bf_changed(self, id):
        #print("enum renamed")
        return 0

    @quite_init_checker
    @stop_if_syncing
    def enum_cmt_changed(self, tid, repeatable_cmt):
        #print("enum renamed")
        return 0

    @quite_init_checker
    @stop_if_syncing
    def enum_member_created(self, id, cid):
        self.bs_enum_modified(id)
        return 0

    # XXX - use enum_member_deleted(self, id, cid) instead?
    @quite_init_checker
    @stop_if_syncing
    def deleting_enum_member(self, id, cid):
        self.bs_enum_modified(id)
        return 0

    #
    #   Struct Hooks
    #

    @quite_init_checker
    @stop_if_syncing
    def struc_created(self, tid):
        #print("struct created")
        sptr = ida_struct.get_struc(tid)
        if not sptr.is_frame():
            self.ida_struct_changed(tid, old_name="")
        return 0

    # XXX - use struc_deleted(self, struc_id) instead?
    @quite_init_checker
    @stop_if_syncing
    def deleting_struc(self, sptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id, deleted=True)
        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_align_changed(self, sptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    # XXX - use struc_renamed(self, sptr) instead?
    @quite_init_checker
    @stop_if_syncing
    def renaming_struc(self, id, oldname, newname):
        sptr = ida_struct.get_struc(id)
        if not sptr.is_frame():
            self.ida_struct_changed(id, old_name=oldname, new_name=newname)
        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_expanded(self, sptr):
        #print("struct expanded")
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_member_created(self, sptr, mptr):
        #print("struc member created")
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_member_deleted(self, sptr, off1, off2):
        #print("struc member deleted")
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_member_renamed(self, sptr, mptr):
        #print(f"struc member renamed: {sptr.id}: {mptr.id}")
        """
        Handles renaming of two things:
        1. Global Structs
        2. Stack Variables

        :param sptr:    Struct Pointer
        :param mptr:    Member Pointer
        :return:
        """
        # struct pointer is actually a stack frame
        if sptr.is_frame():
            stack_frame = sptr
            func_addr = idaapi.get_func_by_frame(stack_frame.id)
            try:
                stack_var_info = compat.get_func_stack_var_info(func_addr)[compat.ida_to_angr_stack_offset(func_addr, mptr.soff)]
            except KeyError:
                l.debug(f"Failed to track an internal changing stack var: {mptr.id}.")
                return 0

            # find the properties of the changed stack var
            angr_offset = compat.ida_to_angr_stack_offset(func_addr, stack_var_info.stack_offset)
            size = stack_var_info.size
            type_str = stack_var_info.type

            # TODO: correct this fix in the get_func_stack_var_info
            new_name = ida_struct.get_member_name(mptr.id)

            # do the change on a new thread
            sv = StackVariable(
                angr_offset, StackOffsetType.IDA, new_name, type_str, size, func_addr
            )
            self.binsync_state_change(
                self.controller.push_artifact,
                sv
            )

        # an actual struct
        else:
            self.ida_struct_changed(sptr.id)

        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_member_changed(self, sptr, mptr):
        #print(f"struc member changed: {sptr.id}, {mptr.id}")

        # struct pointer is actually a stack frame
        if sptr.is_frame():
            stack_frame = sptr
            func_addr = idaapi.get_func_by_frame(stack_frame.id)
            try:
                all_var_info = compat.get_func_stack_var_info(func_addr)
                stack_var_info = all_var_info[compat.ida_to_angr_stack_offset(func_addr, mptr.soff)]
            except KeyError:
                l.debug(f"Failed to track an internal changing stack var: {mptr.id}.")
                return 0

            # find the properties of the changed stack var
            angr_offset = compat.ida_to_angr_stack_offset(func_addr, stack_var_info.stack_offset)
            size = stack_var_info.size
            type_str = stack_var_info.type

            new_name = stack_var_info.name #ida_struct.get_member_name(mptr.id)

            # do the change on a new thread
            sv = StackVariable(
                angr_offset, StackOffsetType.IDA, new_name, type_str, size, func_addr
            )
            self.binsync_state_change(
                self.controller.push_artifact,
                sv
            )
        else:
            self.ida_struct_changed(sptr.id)

        return 0

    @quite_init_checker
    @stop_if_syncing
    def struc_cmt_changed(self, id, repeatable_cmt):
        fullname = ida_struct.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = ida_struct.get_struc_cmt(id, repeatable_cmt)
        return 0

    @quite_init_checker
    @stop_if_syncing
    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # FIXME: sgr_changed is not triggered when a segment register is
        # being deleted by the user, so we need to sent the complete list
        return 0

    @quite_init_checker
    @stop_if_syncing
    def renamed(self, ea, new_name, local_name):
        # #print("renamed(ea = %x, new_name = %s, local_name = %d)" % (ea, new_name, local_name))
        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea) or ida_enum.get_enum_name(ea):
            return 0

        ida_func = idaapi.get_func(ea)
        # global var renaming
        if ida_func is None:
            size = idaapi.get_item_size(ea)
            self.binsync_state_change(
                self.controller.push_artifact,
                GlobalVariable(ea, new_name, size=size)
            )

        # function name renaming
        elif ida_func.start_ea == ea:
            # grab the name instead from ida
            name = idc.get_func_name(ida_func.start_ea)
            self.binsync_state_change(
                self.controller.push_artifact,
                FunctionHeader(name, ida_func.start_ea)
            )

        return 0

    @quite_init_checker
    @stop_if_syncing
    def byte_patched(self, ea, old_value):
        return 0

    @quite_init_checker
    @stop_if_syncing
    def cmt_changed(self, ea, repeatable_cmt):
        if repeatable_cmt:
            cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
            if cmt:
                self.ida_comment_changed(cmt, ea, "cmt")
        return 0

    @quite_init_checker
    @stop_if_syncing
    def range_cmt_changed(self, kind, a, cmt, repeatable):
        #print("range cmt changed")
        # verify it's a function comment
        cmt = idc.get_func_cmt(a.start_ea, repeatable)
        if cmt:
            self.ida_comment_changed(cmt, a.start_ea, "range")

        return 0

    @quite_init_checker
    @stop_if_syncing
    def extra_cmt_changed(self, ea, line_idx, cmt):
        #print("extra cmt changed")
        cmt = ida_bytes.get_cmt(ea, 0)
        if cmt:
            self.ida_comment_changed(cmt, ea, "cmt")
        return 0

    #
    #   Helpers
    #

    def ida_comment_changed(self, comment: str, address: int, cmt_type: str):
        """
        Utility function to catch all types of comment changes.

        @param comment:
        @param address:
        @param cmt_type:
        @return:
        """
        ida_func = idaapi.get_func(address)
        func_addr = ida_func.start_ea if ida_func else None
        kwarg = {"func_addr": func_addr}

        bs_cmt = Comment(address, comment, **kwarg)
        # disass comment changed
        if cmt_type == "cmt":
            self.binsync_state_change(
                self.controller.push_artifact,
                bs_cmt
            )

        # function comment changed
        elif cmt_type == "range":
            # overwrite the entire function comment
            self.binsync_state_change(
                self.controller.push_artifact,
                bs_cmt
            )

        # XXX: other?
        elif cmt_type == "extra":
            return 0

        return 0

    def ida_struct_changed(self, sid: int, old_name=None, new_name=None, deleted=False):
        """
        A utility function to catch all changes that can happen to a struct:
        1. Renames
        2. Member Changes
        3. Deletes

        Currently, any change to a struct will cause the main-thread to re-copy the entire struct from the local
        state into the remote state. This is done so we don't need to have multiple cases for single member changes.

        @param sid:         Struct ID (IDA Thing)
        @param old_name:    Old struct name (before rename)
        @param new_name:    New struct name (after rename)
        @param deleted:     True only when the entire struct has been deleted.
        @return:
        """
        # parse the info of the current struct
        s_name = new_name if new_name else ida_struct.get_struc_name(sid)

        # back out if a stack variable snuck in
        if s_name.startswith("$"):
            return 0

        sptr = ida_struct.get_struc(sid)
        s_size = ida_struct.get_struc_size(sptr)

        # if deleted, finish early
        if deleted:
            self.binsync_state_change(
                self.controller.push_artifact,
                Struct(s_name, None, {})
            )
            return 0

        # convert the ida_struct into a binsync_struct
        binsync_struct = Struct(s_name, s_size, {})
        for mptr in sptr.members:
            mid = mptr.id
            m_name = ida_struct.get_member_name(mid)
            m_off = mptr.soff
            m_type = ida_typeinf.idc_get_type(mptr.id) if mptr.has_ti() else ""
            m_size = ida_struct.get_member_size(mptr)
            binsync_struct.add_struct_member(m_name, m_off, m_type, m_size)

        # make the controller update the local state and push
        old_s_name = old_name if old_name else s_name
        self.binsync_state_change(
            self.controller.push_artifact,
            binsync_struct
        )
        return 0

    def binsync_state_change(self, *args, **kwargs):
        self.controller.async_do_job(*args, **kwargs)


class IDPHooks(ida_idp.IDP_Hooks):
    def __init__(self, controller):
        self.controller = controller
        ida_idp.IDP_Hooks.__init__(self)

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)

    def ev_ending_undo(self, action_name, is_undo):
        """
        This is the hook called by IDA when an undo event occurs
        action name is a vague String description of what changes occured
        is_undo specifies if this action was an undo or a redo
        """
        return 0

    def ev_replaying_undo(self, action_name, vec, is_undo):
        """
        This hook is also called by IDA during the undo
        contains the same information as ev_ending_undo
        vec also contains a short summary of changes incurred
        """
        return 0

class HexRaysHooks:
    def __init__(self, controller):
        self.controller: IDABinSyncController = controller
        super(HexRaysHooks, self).__init__()
        self._available = None
        self._installed = False
        self._cached_funcs = {}
        self.updating_states = threading.Lock()

    def hook(self):
        if not self.controller.decompiler_available:
            return

        ida_hexrays.install_hexrays_callback(self._hxe_callback)
        self._available = True
        self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    @quite_init_checker
    @stop_if_syncing
    def _hxe_callback(self, event, *args):
        if not self._installed:
            return 0

        # this event gets triggered each time that a user changes the view to
        # a different decompilation view. It will also get triggered when staying on the
        # same view but having it refreshed
        if event == ida_hexrays.hxe_func_printed:
            ida_cfunc = args[0]
            func_addr = ida_cfunc.entry_ea
            func = ida_funcs.get_func(func_addr)

            # sanity check
            if func is None:
                return 0

            # run update tasks needed for this function since we are looking at it
            if not self.updating_states.locked():
                with self.updating_states:
                    self.controller.update_states[func_addr].do_updates()

            # create a new cache for unseen funcs
            if func.start_ea not in self._cached_funcs.keys():
                self._cached_funcs[func.start_ea] = {"cmts": [], "header": None}

            # push changes viewable only in decompilation
            self._push_new_comments(func.start_ea)
            self._push_new_func_header(ida_cfunc)

        return 0

    @quite_init_checker
    def _push_new_func_header(self, ida_cfunc):
        # on first time seeing it, we dont want a push
        if not self._cached_funcs[ida_cfunc.entry_ea]["header"]:
            cur_header_str = str(ida_cfunc.type)
            self._cached_funcs[ida_cfunc.entry_ea]["header"] = cur_header_str
            return

        cur_header_str = str(ida_cfunc.type)
        if cur_header_str != self._cached_funcs[ida_cfunc.entry_ea]["header"]:
            # convert to binsync type
            cur_func_header = compat.function_header(ida_cfunc)
            binsync_args = {}
            for idx, arg in cur_func_header.args.items():
                binsync_args[idx] = FunctionArgument(idx, arg.name, arg.type_str, arg.size)

            # send the change
            self.binsync_state_change(
                self.controller.push_artifact,
                cur_func_header
            )

            self._cached_funcs[ida_cfunc.entry_ea]["header"] = cur_header_str

    @staticmethod
    def _get_user_cmts(ea):
        user_cmts = ida_hexrays.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = ida_hexrays.user_cmts_new()
        cmts = {}
        it = ida_hexrays.user_cmts_begin(user_cmts)
        while it != ida_hexrays.user_cmts_end(user_cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmts[tl.ea] = str(cmt)

            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    @quite_init_checker
    def _push_new_comments(self, ea):
        # get the comments for the function
        cmts = HexRaysHooks._get_user_cmts(ea)

        # validate we dont waste time
        if len(cmts) == 0:
            return

        # never do the same push twice
        if cmts != self._cached_funcs[ea]["cmts"]:
            # thread it!
            sync_cmts = [Comment(addr, cmt, decompiled=True) for addr, cmt in cmts.items()]
            for cmt in sync_cmts:
                cmt.func_addr = ea
                self.binsync_state_change(
                    self.controller.push_artifact,
                    cmt
                )

            # cache so we don't double push a copy
            self._cached_funcs[ea]["cmts"] = cmts

    @staticmethod
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
                    vu.refresh_view(False)

    def binsync_state_change(self, *args, **kwargs):
        self.controller.async_do_job(*args, **kwargs)


class MasterHook:
    def __init__(self, controller):
        self.controller = controller

        self.idb_hook = IDBHooks(controller)
        self.idp_hook = IDPHooks(controller)
        self.hexray_hook = HexRaysHooks(controller)

    def hook(self):
        self.idb_hook.hook()
        self.idp_hook.hook()
        self.hexray_hook.hook()
