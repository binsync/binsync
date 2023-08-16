import logging
from typing import Dict

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
            self.ai_interface.RETYPE_VARS_CMD, self.ai_interface.RENAME_VARS_CMD, self.ai_interface.RENAME_FUNCS_CMD,
            self.ai_interface.ANSWER_QUESTION_CMD
        }
        cmt_prepends = {
            self.ai_interface.SUMMARIZE_CMD: "==== AI Summarization ====\n",
            self.ai_interface.ID_SOURCE_CMD: "==== AI Source Guess ====\n",
            self.ai_interface.FIND_VULN_CMD: "==== AI Vuln Guess ====\n",
        }

        func_cmt = ""
        new_func = Function(func.addr, func.size, header=FunctionHeader("", func.addr, args={}), stack_vars={})
        for cmd in self.ai_interface.AI_COMMANDS:
            # TODO: make this more explicit and change what is run
            if cmd not in {self.ai_interface.ANSWER_QUESTION_CMD,
                           self.ai_interface.RENAME_VARS_CMD,
                           self.ai_interface.SUMMARIZE_CMD,
                           self.ai_interface.RENAME_FUNCS_CMD
                           }:
                continue

            try:
                resp = self.ai_interface.query_for_cmd(cmd, decompilation=decompilation)
            except Exception:
                continue

            if not resp:
                continue

            if cmd not in artifact_edit_cmds:
                if cmd == self.ai_interface.ID_SOURCE_CMD:
                    if "http" not in resp:
                        continue

                func_cmt += cmt_prepends.get(cmd, "") + resp + "\n"
                # fake the comment actually being added to decomp
                decompilation = f"/* {Comment.linewrap_comment(resp)} */\n" + decompilation
                changes += 1

            elif cmd == self.ai_interface.RENAME_VARS_CMD:
                all_names = set(sv.name for _, sv in func.stack_vars.items())
                for off, sv in func.stack_vars.items():
                    old_name = sv.name
                    if old_name in resp:
                        proposed_name = resp[old_name]
                        if not proposed_name or proposed_name == old_name or proposed_name in all_names:
                            continue

                        if off not in new_func.stack_vars:
                            new_func.stack_vars[off] = StackVariable(sv.offset, "", None, func.stack_vars[off].size, func.addr)

                        new_func.stack_vars[off].name = proposed_name
                        decompilation = decompilation.replace(old_name, proposed_name)
                        changes += 1

            elif cmd == self.ai_interface.RETYPE_VARS_CMD:
                for off, sv in func.stack_vars.items():
                    old_name = sv.name
                    if old_name in resp:
                        proposed_type = resp[old_name]
                        if not proposed_type or proposed_type == sv.type:
                            continue

                        if off not in new_func.stack_vars:
                            new_func.stack_vars[off] = StackVariable(sv.offset, "", None, func.stack_vars[off].size, func.addr)

                        new_func.stack_vars[off].type = proposed_type
                        # we dont update decompilation here because it would be too weird
                        changes += 1

            elif cmd == self.ai_interface.RENAME_FUNCS_CMD:
                if func.name in resp:
                    proposed_name = resp[func.name]
                    if proposed_name in self.controller.functions() or not proposed_name or proposed_name == func.name:
                        continue

                    new_func.name = proposed_name
                    _l.info(f"Proposing new name for function {func.name} to {proposed_name}")
                    changes += 1

            elif cmd == self.ai_interface.ANSWER_QUESTION_CMD:
                answers: Dict[str, str] = resp
                current_cmts = state.get_func_comments(func.addr)
                for question, answer in answers.items():
                    for _, current_cmt in current_cmts.items():
                        if question in current_cmt.comment:
                            current_cmt.comment += f"\n{answer}"
                            state.set_comment(current_cmt)
                            changes += 1
                            break

        if changes:
            _l.info(f"Suggesting updates to {func} with diff: {new_func}")
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
