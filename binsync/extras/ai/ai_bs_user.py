import logging
import os
import shutil
import time
from pathlib import Path
import argparse
import subprocess
import sys
import tempfile
from typing import Union, Dict
import math
import threading

from binsync.api import load_decompiler_controller, BSController
from binsync.decompilers import ANGR_DECOMPILER
from binsync.data.state import State
from binsync.data import (
    Function, Comment, StackVariable
)
from binsync.ui.qt_objects import (
    QDialog, QMessageBox
)
from binsync.ui.utils import QProgressBarDialog

from dailalib.interfaces import OpenAIInterface
from tqdm import tqdm

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)

class AIBSUser:
    MAX_FUNC_SIZE = 0xffff
    MIN_FUNC_SIZE = 0x25
    DEFAULT_USERNAME = "ai_user"

    def __init__(
        self,
        openai_api_key: str,
        binary_path: Path,
        bs_proj_path: Path = None,
        username: str = DEFAULT_USERNAME,
        copy_project=True,
        decompiler_backend=None,
        base_on=None,
        controller=None,
        model=None,
        progress_callback=None,
        range_str="",
    ):
        self._base_on = base_on
        self.username = username
        self._model = model
        self._progress_callback = progress_callback
        if bs_proj_path is not None:
            bs_proj_path = Path(bs_proj_path)

        # compute the range
        if range_str:
            range_strings = range_str.split("-")
            self.analysis_min = int(range_strings[0], 0)
            self.analysis_max = int(range_strings[1], 0)
        else:
            self.analysis_max = None
            self.analysis_min = None

        # copy or create the project path into the temp dir
        self.decompiler_backend = decompiler_backend
        self.project_path = bs_proj_path or Path(binary_path).with_name(f"{binary_path.with_suffix('').name}.bsproj")
        self._is_tmp = False

        self._on_main_thread = True if self.decompiler_backend is None else False
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
        _l.info(f"AI User working on copied project at: {self.project_path}")
        self.controller: BSController = load_decompiler_controller(
            force_decompiler=self.decompiler_backend, headless=True, binary_path=binary_path, callback_on_push=False
        )
        self.controller.connect(username, str(self.project_path), init_repo=create, single_thread=True)
        self.comments = {}

    def add_ai_user_to_project(self):
        # base all changes on another user's state
        if self._base_on:
            _l.info(f"Basing all AI changes on user {self._base_on}...")
            master_state = self.controller.get_state(user=self._base_on)
            master_state.user = self.username
        else:
            _l.info("Basing AI on current decompiler changes...")
            master_state = self.controller.get_state()

        # collect decompiled functions
        decompiled_functions = self._collect_decompiled_functions()
        t = threading.Thread(
            target=self._query_and_commit_changes,
            args=(master_state, decompiled_functions,)
        )
        t.daemon = True
        t.start()

    def _collect_decompiled_functions(self) -> Dict:
        valid_funcs = [
            addr
            for addr, func in self.controller.functions().items()
            if self._function_is_large_enough(func)
        ]

        if not valid_funcs:
            _l.info("No functions with valid size (small or big), to work on...")
            return {}

        # open a loading bar for progress updates
        pbar = QProgressBarDialog(label_text=f"Decompiling {len(valid_funcs)} functions...")
        pbar.show()
        self._progress_callback = pbar.update_progress

        # decompile important functions first
        decompiled_functions = {}
        update_amt_per_func = math.ceil(100 / len(valid_funcs))
        callback_stub = self._progress_callback if self._progress_callback is not None else lambda x: x
        for func_addr in tqdm(valid_funcs, desc=f"Decompiling {len(valid_funcs)} functions for analysis..."):
            if self.analysis_max is not None and func_addr > self.analysis_max:
                callback_stub(update_amt_per_func)
                continue
            if self.analysis_min is not None and func_addr < self.analysis_min:
                callback_stub(update_amt_per_func)
                continue

            func = self.controller.function(func_addr)
            if func is None:
                callback_stub(update_amt_per_func)
                continue

            decompilation = self.controller.decompile(func_addr)
            if not decompilation:
                callback_stub(update_amt_per_func)
                continue

            decompiled_functions[func.addr] = (decompilation, func)
            callback_stub(update_amt_per_func)

        dlg = QMessageBox(None)
        dlg.setWindowTitle("Locking Changes Done")
        dlg.setText("We've finished decompiling for use with the AI backend. "
        "We will now run the rest of our AI tasks in the background. You can use your decompiler normally now.")
        dlg.exec_()
        return decompiled_functions

    def _query_and_commit_changes(self, state, decompiled_functions):
        total_ai_changes = self.commit_ai_changes_to_state(state, decompiled_functions)
        if total_ai_changes:
            self.controller.client.commit_state(state, msg="AI initiated change to full state")
            self.controller.client.push()

        _l.info(f"Pushed {total_ai_changes} AI initiated changes to user {self.username}")

    def _function_is_large_enough(self, func: Function):
        return self.MIN_FUNC_SIZE <= func.size <= self.MAX_FUNC_SIZE

    def commit_ai_changes_to_state(self, state: State, decompiled_functions):
        ai_initiated_changes = 0
        update_cnt = 0
        for func_addr, (decompilation, func) in tqdm(decompiled_functions.items(), desc=f"Querying AI for {len(decompiled_functions)} funcs..."):
            ai_initiated_changes += self.run_all_ai_commands_for_dec(decompilation, func, state)
            if ai_initiated_changes:
                update_cnt += 1

            if update_cnt >= 3:
                update_cnt = 0
                self.controller.client.commit_state(state, msg="AI Initiated change to functions")
                self.controller.client.push()
                _l.info(f"Pushed some changes to user {self.username}...")

        return ai_initiated_changes

    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function, state: State):
        return 0
