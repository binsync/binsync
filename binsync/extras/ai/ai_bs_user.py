import logging
import os
import shutil
from pathlib import Path
import argparse
import subprocess
import sys
import tempfile
from typing import Union

from binsync.api import load_decompiler_controller, BSController
from binsync.decompilers import ANGR_DECOMPILER
from binsync.decompilers.angr.controller import AngrBSController
from binsync.data import (
    Function, Comment, StackVariable
)

from dailalib.interfaces import OpenAIInterface
from rich.progress import track

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)

class AIBSUser:
    MAX_FUNC_SIZE = 0xffff
    MIN_FUNC_SIZE = 0xb0
    DEFAULT_USERNAME = "AI_user"

    def __init__(
        self,
        openai_api_key: str,
        binary_path: Path,
        bs_proj_path: Path = None,
        username: str = DEFAULT_USERNAME,
        copy_project=True,
        decompiler_backend=None,
        base_on=None,
    ):
        self.username = username
        self._base_on = base_on
        if bs_proj_path is not None:
            bs_proj_path = Path(bs_proj_path)

        # copy or create the project path into the temp dir
        self.decompiler_backend = decompiler_backend
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
            force_decompiler=self.decompiler_backend, headless=True if self.decompiler_backend else False, binary_path=binary_path
        )
        self.controller.connect(username, str(self.project_path), init_repo=create, single_thread=True if self.decompiler_backend else False)

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
        # base all changes on another user's state
        if self._base_on:
            _l.info(f"Basing all AI changes on user {self._base_on}")
            self.controller.fill_all(user=self._base_on)

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
        return 0
