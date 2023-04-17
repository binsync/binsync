import logging
import os
import shutil
from pathlib import Path
import argparse
import subprocess
import sys
import time
import tempfile
from typing import Union

from binsync.api import load_decompiler_controller, BSController
from binsync.decompilers import ANGR_DECOMPILER
from binsync.decompilers.angr.controller import AngrBSController
from binsync.data import (
    Function, State, Comment, StackVariable
)

from dailalib.interfaces import OpenAIInterface
from rich.progress import track

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)

class OpenAIBSUser:
    MAX_FUNC_SIZE = 0xffff
    MIN_FUNC_SIZE = 0xb0
    DEFAULT_USERNAME = "chatgpt_user"

    def __init__(
        self,
        openai_api_key: str,
        binary_path: Path,
        bs_proj_path: Path = None,
        username: str = DEFAULT_USERNAME,
        copy_project=True,
        decompiler_backend=None,
    ):
        self.username = username
        if bs_proj_path is not None:
            bs_proj_path = Path(bs_proj_path)

        # copy or create the project path into the temp dir
        self.decompiler_backend = decompiler_backend or ANGR_DECOMPILER
        self.project_path = bs_proj_path or Path(binary_path).with_name(f"{binary_path.with_suffix('').name}.bsproj")
        self._is_tmp = False
        if copy_project and self.project_path.exists():
            proj_dir = Path(tempfile.mkdtemp())
            shutil.copytree(self.project_path, proj_dir / self.project_path.name)
            self.project_path = proj_dir / self.project_path.name
            self._is_tmp = True

        create = False
        if not self.project_path.exists():
            create = True
            os.mkdir(self.project_path)

        # connect the controller to a GitClient
        self.controller: Union[AngrBSController, BSController] = load_decompiler_controller(
            force_decompiler=self.decompiler_backend, headless=True, binary_path=binary_path
        )
        self.controller.connect(username, str(self.project_path), init_repo=create, single_thread=True)
        self.ai_interface = OpenAIInterface(openai_api_key=openai_api_key, decompiler_controller=self.controller)

    def __del__(self):
        if self._is_tmp:
            shutil.rmtree(self.project_path)

    def add_ai_user_to_project(self):
        _l.info(f"Querying AI for BS changes now...")
        # commit all changes the AI can generate to the master state
        total_ai_changes = self.commit_ai_changes_to_state()
        # ask the git client to push/pull those changes
        self.controller.client.update()
        _l.info(f"Pushed {total_ai_changes} AI initiated changes to user {self.username}")

    def _function_is_large_enough(self, func: Function):
        return self.MIN_FUNC_SIZE <= func.size <= self.MAX_FUNC_SIZE

    def commit_ai_changes_to_state(self):
        ai_initiated_changes = 0
        valid_funcs = [
            addr
            for addr, func in self.controller.functions().items()
            if self._function_is_large_enough(func)
        ]

        for func_addr in track(valid_funcs, description="Querying AI..."):
            func = self.controller.function(func_addr)
            if func is None:
                continue

            decompilation = self.controller.decompile(func_addr)
            if not decompilation:
                continue

            ai_initiated_changes += self.run_all_ai_commands_for_dec(decompilation, func)

        return ai_initiated_changes

    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function):
        changes = 0
        artifact_edit_cmds = {
            self.ai_interface.RETYPE_VARS_CMD, self.ai_interface.RENAME_VARS_CMD, self.ai_interface.RENAME_FUNCS_CMD
        }
        cmt_prepends = {
            self.ai_interface.SUMMARIZE_CMD: "==== AI Summarization ====\n",
            self.ai_interface.ID_SOURCE_CMD: "==== AI Source Guess ====\n",
            self.ai_interface.FIND_VULN_CMD: "==== AI Vuln Guess ====\n",
        }

        new_func: Function = func.copy()
        new_func.header = None
        new_func.stack_vars = {}
        self.controller.push_artifact(new_func)
        for cmd in self.ai_interface.AI_COMMANDS:
            resp = self.ai_interface.query_for_cmd(cmd, decompilation=decompilation)
            if not resp:
                continue

            changes += 1
            if cmd not in artifact_edit_cmds:
                resp = cmt_prepends.get(cmd, "") + resp
                self.controller.push_artifact(Comment(new_func.addr, resp), append=True)
            elif cmd == self.ai_interface.RENAME_VARS_CMD:
                for _, sv in func.stack_vars.items():
                    if sv.name in resp:
                        self.controller.push_artifact(StackVariable(sv.offset, resp[sv.name], None, None, func.addr))
            elif cmd == self.ai_interface.RETYPE_VARS_CMD:
                for _, sv in func.stack_vars.items():
                    if sv.name in resp:
                        self.controller.push_artifact(StackVariable(sv.offset, sv.name, resp[sv.name], None, func.addr))
            elif cmd == self.ai_interface.RENAME_FUNCS_CMD:
                for addr, func in self.controller.functions().items():
                    if func.name in resp:
                        func.name = resp[func.name]
                        self.controller.push_artifact(func)

                        # update the function we are in as well
                        if func.name == new_func.name:
                            new_func.name = resp[func.name]

        return changes


def add_openai_user_to_project(
    openai_api_key: str, binary_path: Path, bs_proj_path: Path, username: str = OpenAIBSUser.DEFAULT_USERNAME,
    headless=False, copy_proj=False, decompiler_backend=None
):
    if headless:
        _headlessly_add_openai_user(openai_api_key, binary_path, bs_proj_path, username=username, decompiler_backend=decompiler_backend)
    else:
        ai_user = OpenAIBSUser(
            openai_api_key=openai_api_key, binary_path=binary_path, bs_proj_path=bs_proj_path,
            username=username, copy_project=copy_proj, decompiler_backend=decompiler_backend
        )
        ai_user.add_ai_user_to_project()


def _headlessly_add_openai_user(
    openai_api_key: str, binary_path: Path, bs_proj_path: Path, username: str = OpenAIBSUser.DEFAULT_USERNAME,
    decompiler_backend=None,
):
    script_path = Path(__file__).absolute()
    python_path = sys.executable
    optional_args = []
    if decompiler_backend:
        optional_args += ["--dec", decompiler_backend]

    subpproc = subprocess.Popen([
        python_path,
        str(script_path),
        openai_api_key,
        str(binary_path),
        "--username",
        username,
        "--proj-path",
        str(bs_proj_path),
    ] + optional_args)
    return subpproc


def _headless_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("openai_api_key", type=str)
    parser.add_argument("binary_path", type=Path)
    parser.add_argument("--proj-path", type=Path)
    parser.add_argument("--username", type=str)
    parser.add_argument("--dec", type=str)

    args = parser.parse_args()
    if args.username is None:
        args.username = OpenAIBSUser.DEFAULT_USERNAME

    add_openai_user_to_project(
        args.openai_api_key, args.binary_path, args.proj_path, username=args.username, headless=False,
        copy_proj=True, decompiler_backend=args.dec if args.dec else None
    )


if __name__ == "__main__":
    _headless_main()
