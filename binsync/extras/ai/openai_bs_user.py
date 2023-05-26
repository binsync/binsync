import logging

from dailalib.interfaces import OpenAIInterface

from binsync.extras.ai.ai_bs_user import AIBSUser
from binsync.data import Function, StackVariable, Comment, State, FunctionHeader

_l = logging.getLogger(__name__)

class OpenAIBSUser(AIBSUser):
    DEFAULT_USERNAME = "chatgpt_user"

    def __init__(self, openai_api_key,  *args, **kwargs):
        super().__init__(openai_api_key, *args, **kwargs)
        self.ai_interface = OpenAIInterface(openai_api_key=openai_api_key, decompiler_controller=self.controller, model=self._model)

    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function, state: State):
        changes = 0
        artifact_edit_cmds = {
            self.ai_interface.RETYPE_VARS_CMD, self.ai_interface.RENAME_VARS_CMD, self.ai_interface.RENAME_FUNCS_CMD
        }
        cmt_prepends = {
            self.ai_interface.SUMMARIZE_CMD: "==== AI Summarization ====\n",
            self.ai_interface.ID_SOURCE_CMD: "==== AI Source Guess ====\n",
            self.ai_interface.FIND_VULN_CMD: "==== AI Vuln Guess ====\n",
        }

        func_cmt = ""
        new_func = Function(func.addr, func.size, header=FunctionHeader("", func.addr, args={}), stack_vars={})
        for cmd in self.ai_interface.AI_COMMANDS:
            # TODO: convert this back to what it was before quals, it's made to be fast for now
            if cmd not in {self.ai_interface.SUMMARIZE_CMD, self.ai_interface.RENAME_FUNCS_CMD, self.ai_interface.FIND_VULN_CMD}:
                continue

            try:
                resp = self.ai_interface.query_for_cmd(cmd, decompilation=decompilation)
            except Exception:
                continue

            if not resp:
                continue

            changes += 1
            if cmd not in artifact_edit_cmds:
                if cmd == self.ai_interface.ID_SOURCE_CMD:
                    if "http" not in resp:
                        continue

                func_cmt += cmt_prepends.get(cmd, "") + resp + "\n"
            elif cmd == self.ai_interface.RENAME_VARS_CMD:
                all_names = set(sv.name for _, sv in func.stack_vars.items())
                for off, sv in func.stack_vars.items():
                    if sv.name in resp:
                        proposed_name = resp[sv.name]
                        if proposed_name not in all_names:
                            new_func.stack_vars[off] = StackVariable(sv.offset, proposed_name, None, func.stack_vars[off].size, func.addr)
                            #self.controller.push_artifact(StackVariable(sv.offset, proposed_name, None, None, func.addr))
                            #self.controller.schedule_job(
                            #    self.controller.push_artifact,
                            #    StackVariable(sv.offset, proposed_name, None, None, func.addr),
                            #    #blocking=True
                            #)

            elif cmd == self.ai_interface.RETYPE_VARS_CMD:
                for off, sv in func.stack_vars.items():
                    if sv.name in resp:
                        new_func.stack_vars[off] = StackVariable(sv.offset, "", resp[sv.name], func.stack_vars[off].size, func.addr)
                        #self.controller.push_artifact(StackVariable(sv.offset, sv.name, resp[sv.name], None, func.addr))
                        #self.controller.schedule_job(
                        #    self.controller.push_artifact,
                        #    StackVariable(sv.offset, sv.name, resp[sv.name], None, func.addr),
                        #    #blocking=True
                        #)

            elif cmd == self.ai_interface.RENAME_FUNCS_CMD:
                for addr, _func in self.controller.functions().items():
                    if _func.name in resp:
                        proposed_name = resp[_func.name]
                        if proposed_name in self.controller.functions() or not proposed_name:
                            continue

                        # this is the current function we are working in
                        if _func.name == func.name:
                            new_func.name = proposed_name
                            changes += 1
                            continue

                        # this is some external function
                        if _func.addr not in state.functions:
                            state.functions[_func.addr] = Function(_func.addr, _func.size)
                        state.functions[_func.addr].name = proposed_name
                        _l.info(f"Proposing new name for function {_func} to {proposed_name}")
                        changes += 1

        if changes:
            _l.info(f"Proposing new name for function {func} to {new_func}")
            state.set_function(new_func)

        # send full function comment
        if func_cmt:
            state.set_comment(Comment(new_func.addr, func_cmt, func_addr=new_func.addr, decompiled=True), append=True)
            #self.controller.push_artifact(Comment(new_func.addr, func_cmt, func_addr=new_func.addr, decompiled=True), append=True)
            #self.controller.fill_comment(new_func.addr, user=self.username, artifact=Comment(new_func.addr, func_cmt, func_addr=new_func.addr, decompiled=True), append=True)
            #self.controller.schedule_job(
            #    self.controller.push_artifact,
            #    Comment(new_func.addr, func_cmt, func_addr=new_func.addr, decompiled=True),
            #    blocking=False,
            #    append=True
            #)

        return changes
