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
# that we try to track when a user makes a change. For instance, the function
# `cmt_changed` is activated every time a user changes a disassembly comment,
# allowing us to send the new comment to be queued in the Controller actions.
#
# ----------------------------------------------------------------------------

from functools import wraps

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
import idaapi
import idc

from . import compat
from .controller import BinsyncController


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

#
#   IDA Change Hooks
#


class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self, controller):
        ida_idp.IDB_Hooks.__init__(self)
        self.controller: BinsyncController = controller
        self.last_local_type = None

    @quite_init_checker
    def local_types_changed(self):
        print("local type changed")
        return

        changed_types = []
        # self._plugin.logger.trace(self._plugin.core.local_type_map)
        for i in range(1, ida_typeinf.get_ordinal_qty(ida_typeinf.get_idati())):
            t = ImportLocalType(i)
            if t and t.name and ida_struct.get_struc_id(t.name) == ida_idaapi.BADADDR and ida_enum.get_enum(
                    t.name) == ida_idaapi.BADADDR:
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old and not t.isEqual(t_old):
                        changed_types.append((t_old.to_tuple(), t.to_tuple()))
                    elif t_old is None and i in self._plugin.core.delete_candidates:
                        if not self._plugin.core.delete_candidates[i].isEqual(t):
                            changed_types.append((self._plugin.core.delete_candidates[i].to_tuple(), t.to_tuple()))
                        del self._plugin.core.delete_candidates[i]

                else:
                    changed_types.append((None, t.to_tuple()))
            if t is None:
                assert i in self._plugin.core.local_type_map
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old != t:
                        self._plugin.core.delete_candidates[i] = t_old
                    elif i in self._plugin.core.delete_candidates:
                        # changed_types.append((self._plugin.core.delete_candidates[i],None))
                        del self._plugin.core.delete_candidates[i]

                    # t_old = self._plugin.core.local_type_map[i]
                    # changed_types.append((t_old,None))
        # self._plugin.logger.trace(changed_types)
        if fDebug:
            pydevd_pycharm.settrace('localhost', port=2233, stdoutToServer=True, stderrToServer=True, suspend=False)
        self._plugin.logger.trace("Changed_types: %s" % list(
            map(lambda x: (x[0][0] if x[0] else None, x[1][0] if x[1] else None), changed_types)))
        if len(changed_types) > 0:
            self._send_packet(evt.LocalTypesChangedEvent(changed_types))
        self._plugin.core.update_local_types_map()
        return 0

    @quite_init_checker
    def ti_changed(self, ea, type, fname):
        return
        name = ""
        if ida_struct.is_member_id(ea):
            name = ida_struct.get_struc_name(ea)
        type = ida_typeinf.idc_get_type_raw(ea)
        self._send_packet(
            evt.TiChangedEvent(ea, (ParseTypeString(type[0]) if type else [], type[1] if type else None), name))
        return 0

    @quite_init_checker
    def enum_created(self, enum):
        print("enum created")
        return

        name = ida_enum.get_enum_name(enum)
        self._send_packet(evt.EnumCreatedEvent(enum, name))
        return 0

    # XXX - use enum_deleted(self, id) instead?
    @quite_init_checker
    def deleting_enum(self, id):
        print("enum deleted")
        return 0
        enum_name = ida_enum.get_enum_name(id)

    # XXX - use enum_renamed(self, id) instead?
    @quite_init_checker
    def renaming_enum(self, id, is_enum, newname):
        print("enum renamed")
        return

        if is_enum:
            oldname = ida_enum.get_enum_name(id)
        else:
            oldname = ida_enum.get_enum_member_name(id)
        self._send_packet(evt.EnumRenamedEvent(oldname, newname, is_enum))
        return 0

    @quite_init_checker
    def enum_bf_changed(self, id):
        print("enum renamed")
        return
        bf_flag = 1 if ida_enum.is_bf(id) else 0
        ename = ida_enum.get_enum_name(id)
        self._send_packet(evt.EnumBfChangedEvent(ename, bf_flag))
        return 0

    @quite_init_checker
    def enum_cmt_changed(self, tid, repeatable_cmt):
        print("enum renamed")
        return
        cmt = ida_enum.get_enum_cmt(tid, repeatable_cmt)
        emname = ida_enum.get_enum_name(tid)
        self._send_packet(evt.EnumCmtChangedEvent(emname, cmt, repeatable_cmt))
        return 0

    @quite_init_checker
    def enum_member_created(self, id, cid):
        print("enum member created")
        return
        ename = ida_enum.get_enum_name(id)
        name = ida_enum.get_enum_member_name(cid)
        value = ida_enum.get_enum_member_value(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberCreatedEvent(ename, name, value, bmask)
        )
        return 0

    # XXX - use enum_member_deleted(self, id, cid) instead?
    @quite_init_checker
    def deleting_enum_member(self, id, cid):
        print("enum member")
        return
        ename = ida_enum.get_enum_name(id)
        value = ida_enum.get_enum_member_value(cid)
        serial = ida_enum.get_enum_member_serial(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberDeletedEvent(ename, value, serial, bmask)
        )
        return 0

    @quite_init_checker
    def struc_created(self, tid):
        print("struct created")
        return
        name = ida_struct.get_struc_name(tid)
        is_union = ida_struct.is_union(tid)
        self._send_packet(evt.StrucCreatedEvent(tid, name, is_union))
        return 0

    # XXX - use struc_deleted(self, struc_id) instead?
    @quite_init_checker
    def deleting_struc(self, sptr):
        print("struct deleted")
        return
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.StrucDeletedEvent(sname))
        return 0

    @quite_init_checker
    def struc_align_changed(self, sptr):
        print("struc_align_changed() not implemented yet")
        return 0

    # XXX - use struc_renamed(self, sptr) instead?
    @quite_init_checker
    def renaming_struc(self, id, oldname, newname):
        print(f"rename struc: {id} | {oldname} | {newname}")
        return 0

    # XXX - use struc_expanded(self, sptr) instead
    @quite_init_checker
    def expanding_struc(self, sptr, offset, delta):
        sname = ida_struct.get_struc_name(sptr.id)
        return 0

    @quite_init_checker
    def struc_member_created(self, sptr, mptr):
        print("struc member created")
        extra = {}
        sname = ida_struct.get_struc_name(sptr.id)
        fieldname = ida_struct.get_member_name(mptr.id)
        offset = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        nbytes = mptr.eoff if mptr.unimem() else mptr.eoff - mptr.soff
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
            # Is it really possible to create an enum?
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
            elif flag & ida_bytes.stru_flag():
                extra["struc_name"] = ida_struct.get_struc_name(mt.tid)
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
        return 0

    @quite_init_checker
    def struc_member_deleted(self, sptr, off1, off2):
        sname = ida_struct.get_struc_name(sptr.id)
        return 0

    @quite_init_checker
    def renaming_struc_member(self, sptr, mptr, newname):
        """
        Handles renaming of two things:
        1. Global Structs
        2. Stack Variables

        :param sptr:    Struct Pointer
        :param mptr:    Member Pointer
        :param newname: New Member Name
        :return:
        """

        sname = ida_struct.get_struc_name(sptr.id)
        s_type = compat.parse_struct_type(sname)

        # stack offset variable
        if isinstance(s_type, int):
            func_addr = s_type

            # compute stack frame for offset
            frame = idaapi.get_frame(func_addr)
            frame_size = idc.get_struc_size(frame)
            last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))

            # stack offset
            stack_offset = mptr.soff - frame_size + last_member_size
            size = idaapi.get_member_size(mptr)
            type_str = self.controller._get_type_str(mptr.flag)

            # do the change on a new thread
            self.controller.make_controller_cmd(self.controller.push_stack_variable,
                                                func_addr, stack_offset, newname, type_str, size)



        # actual struct
        elif isinstance(s_type, str):
            print("Not implemented")

        else:
            print("Error: bad parsing")

        return 0

    @quite_init_checker
    def struc_member_changed(self, sptr, mptr):
        print("struc member changed")
        extra = {}

        sname = ida_struct.get_struc_name(sptr.id)
        soff = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
            elif flag & ida_bytes.stru_flag():
                extra["struc_name"] = ida_struct.get_struc_name(mt.tid)
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
        return 0

    @quite_init_checker
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
    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # FIXME: sgr_changed is not triggered when a segment register is
        # being deleted by the user, so we need to sent the complete list
        return 0

    @quite_init_checker
    def renamed(self, ea, new_name, local_name):
        print("renamed(ea = %x, new_name = %s, local_name = %d)" % (ea, new_name, local_name))
        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea) or ida_enum.get_enum_name(ea):
            # Drop hook to avoid duplicate since already handled by the following hooks:
            # - renaming_struc_member() -> sends 'StrucMemberRenamedEvent'
            # - renaming_struc() -> sends 'StrucRenamedEvent'
            # - renaming_enum() -> sends 'EnumRenamedEvent'
            return 0

        # confirm we are renaming a function
        ida_func = idaapi.get_func(ea)
        if ida_func is None:
            return 0

        # grab the name instead from ida
        name = idc.get_func_name(ida_func.start_ea)
        self.controller.make_controller_cmd(self.controller.push_function_name, ida_func.start_ea, name)

        return 0

    @quite_init_checker
    def byte_patched(self, ea, old_value):
        return 0

    @quite_init_checker
    def cmt_changed(self, ea, repeatable_cmt):
        print("cmt changed")
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        if cmt:
            self.ida_comment_changed(cmt, ea, "cmt")
        return 0

    @quite_init_checker
    def range_cmt_changed(self, kind, a, cmt, repeatable):
        print("range cmt changed")
        # verify it's a function comment
        cmt = idc.get_func_cmt(a.start_ea, repeatable)
        if cmt:
            self.ida_comment_changed(cmt, a.start_ea, "range")

        return 0

    @quite_init_checker
    def extra_cmt_changed(self, ea, line_idx, cmt):
        print("extra cmt changed")
        cmt = ida_bytes.get_cmt(ea, 0)
        if cmt:
            self.ida_comment_changed(cmt, ea, "cmt")
        return 0

    def ida_comment_changed(self, comment, address, cmt_type):
        # disass comment changed
        if cmt_type == "cmt":
            # find the location this comment exists
            func_addr = idaapi.get_func(address).start_ea
            self.controller.make_controller_cmd(self.controller.push_comment, address, comment)


        # function comment changed
        elif cmt_type == "range":
            # overwrite the entire function comment
            self.controller.make_controller_cmd(self.controller.push_func_comment, address, comment)

        # XXX: other?
        elif cmt_type == "extra":
            return 0

        return 0

class IDPHooks(ida_idp.IDP_Hooks):
    def __init__(self, controller):
        self.controller = controller
        ida_idp.IDP_Hooks.__init__(self)

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)


class HexRaysHooks:
    def __init__(self, controller):
        self.controller = controller
        super(HexRaysHooks, self).__init__()
        self._available = None
        self._installed = False
        self._cached_funcs = {}

    def hook(self):
        if self._available is None:
            if not ida_hexrays.init_hexrays_plugin():
                self._plugin.logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                ida_hexrays.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    @quite_init_checker
    def _hxe_callback(self, event, *_):
        if not self._installed:
            return 0

        if event == ida_hexrays.hxe_func_printed:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)

            print("INSIDE HXE CALLBACK!")
            if func is None:
                return 0

            if func.start_ea not in self._cached_funcs.keys():
                self._cached_funcs[func.start_ea] = {"cmts": []}

            self._update_user_cmts(func.start_ea)
        return 0

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

            print(f"TL EA: {tl.ea} | TL ITP: {tl.itp}")
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    @quite_init_checker
    def _update_user_cmts(self, ea):
        # get the comments for the function
        cmts = HexRaysHooks._get_user_cmts(ea)

        # validate we dont waste time
        if len(cmts) == 0:
            return

        print(f"COMMENTS: {cmts}")
        # never do the same push twice
        if cmts != self._cached_funcs[ea]["cmts"]:
            # thread it!
            print(f"SENDING {cmts}")
            self.controller.make_controller_cmd(self.controller.push_comments, cmts)

            # cache so we don't double push a copy
            self._cached_funcs[ea]["cmts"] = cmts

    @staticmethod
    def _get_user_lvar_settings(ea):
        dct = {}
        lvinf = ida_hexrays.lvar_uservec_t()
        ret = ida_hexrays.restore_user_lvar_settings(lvinf, ea)
        # print("_get_user_lvar_settings: ret = %x" % ret)
        if ret:
            dct["lvvec"] = []
            for lv in lvinf.lvvec:
                dct["lvvec"].append(HexRaysHooks._get_lvar_saved_info(lv))
            if hasattr(lvinf, "sizes"):
                dct["sizes"] = list(lvinf.sizes)
            dct["lmaps"] = []
            it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
            while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
                key = ida_hexrays.lvar_mapping_first(it)
                key = HexRaysHooks._get_lvar_locator(key)
                val = ida_hexrays.lvar_mapping_second(it)
                val = HexRaysHooks._get_lvar_locator(val)
                dct["lmaps"].append((key, val))
                it = ida_hexrays.lvar_mapping_next(it)
            dct["stkoff_delta"] = lvinf.stkoff_delta
            dct["ulv_flags"] = lvinf.ulv_flags
        return dct

    @staticmethod
    def _get_lvar_saved_info(lv):
        return

    @staticmethod
    def _get_tinfo(type):
        if type.empty():
            return None, None, None, None

        type, fields, fldcmts = type.serialize()

    @staticmethod
    def _get_lvar_locator(ll):
        return {
            "location": HexRaysHooks._get_vdloc(ll.location),
            "defea": ll.defea,
        }

    @staticmethod
    def _get_vdloc(location):
        return {
            "atype": location.atype(),
            "reg1": location.reg1(),
            "reg2": location.reg2(),
            "stkoff": location.stkoff(),
            "ea": location.get_ea(),
        }

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
