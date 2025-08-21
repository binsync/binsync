import logging
import threading
import datetime
import time
from functools import wraps
from typing import Dict, Optional, List

from libbs.api.utils import progress_bar
from libbs.artifacts import (
    Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct, FunctionArgument, StructMember, Typedef, Segment
)
from libbs.api import DecompilerInterface

from binsync.core.client import Client
from binsync.core.state import State
from binsync.core.user import User
from binsync.configuration import BinSyncBSConfig

_l = logging.getLogger(name=__name__)

BUSY_LOOP_COOLDOWN = 0.5


def init_checker(f):
    @wraps(f)
    def _init_check(self, *args, **kwargs):
        if not self.check_client():
            raise RuntimeError("Please connect to a repo first.")
        return f(self, *args, **kwargs)
    
    return _init_check


class SyncControlStatus:
    CONNECTED = 0
    CONNECTED_NO_REMOTE = 1
    DISCONNECTED = 2
    LOADING = 3


class Controller:
    """
    Simplified BinSync Controller for single-branch collaboration.
    All users work on the same main branch with automatic conflict resolution.
    """
    
    CHANGE_WATCHERS = (
        FunctionHeader, StackVariable, Comment, GlobalVariable, Enum, Struct, Typedef, Segment
    )

    ARTIFACT_SET_MAP = {
        Function: State.set_function,
        FunctionHeader: State.set_function_header,
        StackVariable: State.set_stack_variable,
        Comment: State.set_comment,
        GlobalVariable: State.set_global_var,
        Struct: State.set_struct,
        Enum: State.set_enum,
        Typedef: State.set_typedef,
        Segment: State.set_segment
    }

    ARTIFACT_GET_MAP = {
        Function: State.get_function,
        FunctionHeader: State.get_function_header,
        StackVariable: State.get_stack_variable,
        Comment: State.get_comment,
        GlobalVariable: State.get_global_var,
        Struct: State.get_struct,
        Enum: State.get_enum,
        Typedef: State.get_typedef,
        Segment: State.get_segment
    }

    def __init__(
        self, 
        decompiler_interface: DecompilerInterface = None, 
        headless=False, 
        auto_commit=True, 
        reload_time=10,
        **kwargs
    ):
        self.headless = headless
        self.reload_time = reload_time
        
        if decompiler_interface is None:
            self.deci = DecompilerInterface.discover(thread_artifact_callbacks=False)
        else:
            self.deci = decompiler_interface

        # client created on connection
        self.client = None  # type: Optional[Client]

        # ui callbacks
        self.ui_callback = None  # func(state: State, changes: List[Dict])
        self.ctx_change_callback = None  # func()
        self._last_reload = None
        self.last_active_func = None
        self._got_first_state = False

        # settings
        self._auto_commit_enabled = auto_commit
        self.auto_push_enabled = True
        self.auto_pull_enabled = True

        # threading
        self._run_updater_threads = False
        self.update_thread = threading.Thread(target=self.updater_routine, daemon=True)
        
        # change tracking for UI
        self._change_history: List[Dict] = []
        self._last_state_snapshot: Optional[State] = None

        # artifact change callbacks
        self.deci.should_watch_artifacts = self.should_watch_artifacts
        for typ in self.CHANGE_WATCHERS:
            self.deci.artifact_change_callbacks[typ].append(self._commit_hook_based_changes)

        # artifact map
        self.artifact_dict_map = {
            Function: self.deci.functions,
            Comment: self.deci.comments,
            GlobalVariable: self.deci.global_vars,
            Enum: self.deci.enums,
            Typedef: self.deci.typedefs,
            Struct: self.deci.structs,
            Patch: self.deci.patches,
            Segment: self.deci.segments
        }
        
        # configuration
        self.config = None

    def connect(self, user, path, init_repo=False, remote_url=None, **kwargs):
        """Connect to a BinSync repository"""
        binary_hash = self.deci.binary_hash
        self.client = Client(
            user=user,
            repo_path=path,
            binary_hash=binary_hash,
            remote_url=remote_url,
            init_repo=init_repo,
            **kwargs
        )
        
        # Initialize state tracking
        self._last_state_snapshot = self.client.get_state().copy()
        
        # Start background threads
        self.start_worker_routines()
        
        return []  # No connection warnings in simplified version

    def check_client(self):
        return self.client is not None

    def status(self):
        if self.check_client():
            if self.client.remote_url:
                return SyncControlStatus.CONNECTED if self._got_first_state else SyncControlStatus.LOADING
            return SyncControlStatus.CONNECTED_NO_REMOTE
        return SyncControlStatus.DISCONNECTED

    def status_string(self):
        stat = self.status()
        if stat == SyncControlStatus.CONNECTED:
            return f"<font color=#1eba06>{self.client.user}</font>"
        elif stat == SyncControlStatus.CONNECTED_NO_REMOTE:
            return f"<font color=#e7b416>{self.client.user}</font>"
        elif stat == SyncControlStatus.LOADING:
            return f"<font color=#ffa500>Loading...</font>"
        else:
            return "<font color=#cc3232>Disconnected</font>"

    def should_watch_artifacts(self):
        return bool(self.check_client())

    def _commit_hook_based_changes(self, *args, **kwargs):
        """Callback for artifact changes from the decompiler"""
        if self.should_watch_artifacts():
            self.commit_artifact(*args, **kwargs)

    @init_checker
    def commit_artifact(self, artifact: Artifact, commit_msg=None, **kwargs) -> bool:
        """Commit an artifact change to the shared state"""
        _l.debug(f"Committing artifact: {artifact}")
        if not artifact:
            _l.warning(f"Attempting to commit a None artifact, skipping...")
            return False

        try:
            set_art_func = self.ARTIFACT_SET_MAP[artifact.__class__]
        except KeyError:
            _l.info(f"Attempting to commit an unsupported Artifact of type {artifact}")
            return False

        state = self.client.get_state()
        
        # Set the artifact in the state
        was_set = set_art_func(state, artifact, **kwargs)
        
        if was_set and self._auto_commit_enabled:
            # Record the change for UI history
            self._record_change(self.client.user, "updated", artifact)
            
            # Commit to repository
            success = self.client.commit_state(state, commit_msg)
            if success and self.auto_push_enabled:
                self.client.push_changes()
                
        return was_set

    def _record_change(self, user: str, operation: str, artifact: Artifact):
        """Record a change for the UI history"""
        change = {
            "user": user,
            "operation": operation,
            "artifact": artifact,
            "timestamp": datetime.datetime.now(tz=datetime.timezone.utc),
            "description": self._get_artifact_description(artifact)
        }
        self._change_history.append(change)
        
        # Keep only last 1000 changes
        if len(self._change_history) > 1000:
            self._change_history = self._change_history[-1000:]

    def _get_artifact_description(self, artifact: Artifact) -> str:
        """Get a user-friendly description of an artifact"""
        if isinstance(artifact, Function):
            name = artifact.name or f"sub_{artifact.addr:x}"
            return f"function@{name}"
        elif isinstance(artifact, FunctionHeader):
            return f"function_header@{artifact.addr:x}"
        elif isinstance(artifact, StackVariable):
            return f"stack_var@{artifact.name or 'unnamed'}"
        elif isinstance(artifact, Comment):
            return f"comment@{artifact.addr:x}"
        elif isinstance(artifact, GlobalVariable):
            return f"global@{artifact.name or artifact.addr:x}"
        elif isinstance(artifact, Struct):
            return f"struct@{artifact.name}"
        elif isinstance(artifact, Enum):
            return f"enum@{artifact.name}"
        elif isinstance(artifact, Typedef):
            return f"typedef@{artifact.name}"
        elif isinstance(artifact, Segment):
            return f"segment@{artifact.name}"
        else:
            return f"{artifact.__class__.__name__}@{getattr(artifact, 'addr', 'unknown')}"

    def updater_routine(self):
        """Background routine for pulling updates and notifying UI"""
        while self._run_updater_threads:
            time.sleep(BUSY_LOOP_COOLDOWN)
            now = datetime.datetime.now(tz=datetime.timezone.utc)

            if not self.check_client():
                continue

            # Pull updates periodically
            if (self._last_reload is None or 
                int(now.timestamp() - self._last_reload.timestamp()) >= self.reload_time):
                
                if self.auto_pull_enabled:
                    self.client.pull_and_update()
                
                self._last_reload = now
                self._got_first_state = True
                
                # Check for state changes and update UI
                self._check_for_state_changes()

            # Update context if needed
            if not self.headless and self.ctx_change_callback:
                self._check_and_notify_ctx()

    def _check_for_state_changes(self):
        """Check for changes in the state and update change history"""
        if not self.client:
            return
            
        current_state = self.client.get_state()
        if not self._last_state_snapshot:
            self._last_state_snapshot = current_state.copy()
            return

        # Compare states and record external changes
        changes = self._detect_state_changes(self._last_state_snapshot, current_state)
        for change in changes:
            if change["user"] != self.client.user:  # Only record external changes
                self._change_history.append(change)

        # Update UI if there are changes
        if changes and self.ui_callback:
            self.ui_callback(current_state, self._change_history)

        self._last_state_snapshot = current_state.copy()

    def _detect_state_changes(self, old_state: State, new_state: State) -> List[Dict]:
        """Detect changes between two states"""
        changes = []
        
        # Check functions
        for addr, func in new_state.functions.items():
            if addr not in old_state.functions:
                changes.append({
                    "user": new_state.user,
                    "operation": "created",
                    "artifact": func,
                    "timestamp": func.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(func)
                })
            elif old_state.functions[addr] != func:
                changes.append({
                    "user": new_state.user,
                    "operation": "updated",
                    "artifact": func,
                    "timestamp": func.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(func)
                })

        # Check comments
        for addr, comment in new_state.comments.items():
            if addr not in old_state.comments:
                changes.append({
                    "user": new_state.user,
                    "operation": "created",
                    "artifact": comment,
                    "timestamp": comment.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(comment)
                })
            elif old_state.comments[addr] != comment:
                changes.append({
                    "user": new_state.user,
                    "operation": "updated",
                    "artifact": comment,
                    "timestamp": comment.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(comment)
                })

        # Check structs, enums, etc. (similar pattern)
        for name, struct in new_state.structs.items():
            if name not in old_state.structs:
                changes.append({
                    "user": new_state.user,
                    "operation": "created",
                    "artifact": struct,
                    "timestamp": struct.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(struct)
                })
            elif old_state.structs[name] != struct:
                changes.append({
                    "user": new_state.user,
                    "operation": "updated",
                    "artifact": struct,
                    "timestamp": struct.last_change or datetime.datetime.now(tz=datetime.timezone.utc),
                    "description": self._get_artifact_description(struct)
                })

        return changes

    def _check_and_notify_ctx(self):
        """Check for context changes and notify UI"""
        active_ctx = self.deci.gui_active_context()
        if (active_ctx is None or 
            active_ctx.func_addr is None or
            (self.last_active_func is not None and active_ctx.func_addr == self.last_active_func.addr)):
            return

        curr_func = self.deci.fast_get_function(active_ctx.func_addr)
        self.last_active_func = curr_func
        if self.ctx_change_callback:
            self.ctx_change_callback()

    def start_worker_routines(self):
        """Start background worker threads"""
        self._run_updater_threads = True
        self.update_thread.start()
        self.deci.start_artifact_watchers()

    def stop_worker_routines(self):
        """Stop background worker threads"""
        self._run_updater_threads = False

    def shutdown(self):
        """Shutdown the controller"""
        self.stop_worker_routines()
        if self.client:
            self.client.shutdown()
        self.deci.shutdown()

    def get_change_history(self) -> List[Dict]:
        """Get the change history for the UI"""
        return self._change_history.copy()

    @init_checker
    def force_push_artifact(self, artifact: Artifact):
        """Force push a single artifact from the decompiler"""
        state = self.client.get_state()
        set_art_func = self.ARTIFACT_SET_MAP[artifact.__class__]
        set_art_func(state, artifact)
        
        self._record_change(self.client.user, "force_pushed", artifact)
        
        success = self.client.commit_state(state, f"Force pushed {artifact}")
        if success and self.auto_push_enabled:
            self.client.push_changes()
        
        return success

    @property
    def auto_commit_enabled(self):
        return self._auto_commit_enabled

    @auto_commit_enabled.setter
    def auto_commit_enabled(self, val):
        self._auto_commit_enabled = val
        
    def load_saved_config(self):
        """Load saved configuration"""
        try:
            config = BinSyncBSConfig()
            config.load()
            return config
        except Exception as e:
            _l.debug(f"Failed to load saved config: {e}")
            return None