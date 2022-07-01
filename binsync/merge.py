import logging

from binsync.data.state import State

l = logging.getLogger(__name__)

class MergeState:
    def __init__(self, mstr_state: State, trgt_state: State, func_addr: int):
        self.mstr_state = mstr_state
        self.trgt_state = trgt_state
        self.func_addr = func_addr

        self.cmt_diff = {}
        self.var_diff = {}
        self.func_name_diff = {}
        self.conflicts = False

    def _gen_state_diff(self):
        self.conflicts |= self._gen_func_name_diff()
        self.conflicts |= self._gen_var_diff()
        self.conflicts |= self._gen_cmt_diff()

    def _gen_cmt_diff(self):
        conflicts = False

        try:
            mstr_cmts = self.mstr_state.comments[self.func_addr]
            trgt_cmts = self.trgt_state.comments[self.func_addr]
        except KeyError:
            return conflicts

        for addr in mstr_cmts:
            try:
                after = trgt_cmts[addr]
            except KeyError:
                continue

            before = mstr_cmts[addr]
            if before.decompiled != after.decompiled:
                continue

            if before != after:
                self.cmt_diff[addr] = {'mstr': before, 'trgt': after}
                conflicts = True

        return conflicts

    def _gen_var_diff(self):
        conflicts = False

        # check for existence of vars both in master and target
        try:
            mstr_vars = self.mstr_state.stack_variables[self.func_addr]
            trgt_vars = self.trgt_state.stack_variables[self.func_addr]
        except KeyError:
            return conflicts

        # validate for every master var
        for off in mstr_vars:
            try:
                after = trgt_vars[off]
            except KeyError:
                continue

            before = mstr_vars[off]
            if before != after:
                self.var_diff[off] = {'mstr': before.name, 'trgt': after.name}
                conflicts = True

        return conflicts

    def _gen_func_name_diff(self):
        conflicts = False

        try:
            before = self.mstr_state.functions[self.func_addr]
            after = self.trgt_state.functions[self.func_addr]
        except KeyError:
            return conflicts

        if before != after:
            self.func_name_diff['mstr'] = before.name
            self.func_name_diff['trgt'] = after.name
            conflicts = True

        return conflicts


class Merge:
    def __init__(self):
        pass
