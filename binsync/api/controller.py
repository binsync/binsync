import logging
import threading
import datetime
import time
import math
from functools import wraps
from typing import Dict, Iterable, Optional, Union, TypeVar, Callable, List

import binsync.data
from binsync.data import ProjectConfig
from binsync.api.artifact_lifter import BSArtifactLifter
from binsync.core.client import Client, SchedSpeed, Scheduler, Job
from binsync.api.type_parser import BSTypeParser, BSType
from binsync.api.utils import progress_bar
from binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct
)

_l = logging.getLogger(name=__name__)


#
# State Checking Decorators
#

def init_checker(f):
    @wraps(f)
    def _init_check(self, *args, **kwargs):
        if not self.check_client():
            raise RuntimeError("Please connect to a repo first.")
        return f(self, *args, **kwargs)

    return _init_check


def fill_event(f):
    @wraps(f)
    def _fill_event(self: "BSController", *args, **kwargs):
        return self.fill_event_handler(f, *args, **kwargs)

    return _fill_event

#
# Description Constants
#


# https://stackoverflow.com/questions/10926328
BUSY_LOOP_COOLDOWN = 0.5
GET_MANY = True
FILL_MANY = True


class SyncControlStatus:
    CONNECTED = 0
    CONNECTED_NO_REMOTE = 1
    DISCONNECTED = 2


class MergeLevel:
    OVERWRITE = 0
    NON_CONFLICTING = 1
    MERGE = 2


class FakeSyncLock:
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


#
#   Controller
#

class BSController:

    ARTIFACT_SET_MAP = {
        Function: State.set_function,
        FunctionHeader: State.set_function_header,
        StackVariable: State.set_stack_variable,
        Comment: State.set_comment,
        GlobalVariable: State.set_global_var,
        Struct: State.set_struct,
        Enum: State.set_enum
    }

    ARTIFACT_GET_MAP = {
        Function: State.get_function,
        (Function, GET_MANY): State.get_functions,
        FunctionHeader: State.get_function_header,
        (FunctionHeader, GET_MANY): State.get_function_headers,
        StackVariable: State.get_stack_variable,
        (StackVariable, GET_MANY): State.get_stack_variables,
        Comment: State.get_comment,
        (Comment, GET_MANY): State.get_func_comments,
        GlobalVariable: State.get_global_var,
        (GlobalVariable, GET_MANY): State.get_global_vars,
        Struct: State.get_struct,
        (Struct, GET_MANY): State.get_structs,
        Enum: State.get_enum,
        (Enum, GET_MANY): State.get_enums,
    }

    """
    The BinSync Controller is the main interface for syncing with the BinSync Client which preforms git tasks
    such as pull and push. In the Controller higher-level tasks are done such as updating UI with changes
    and preforming syncs and pushes on data users need/change.

    All class properties that have a "= None" means they must be set during runtime by an outside process.
    The client will be set on connection. The ctx_change_callback will be set by an outside UI

    """
    def __init__(self, artifact_lifter=None, headless=False, auto_commit=True, reload_time=10, **kwargs):
        self.headless = headless
        self.reload_time = reload_time
        self.artifact_lifer: BSArtifactLifter = artifact_lifter

        # client created on connection
        self.client = None  # type: Optional[Client]

        # ui callback created on UI init
        self.ui_callback = None  # func(states: List[State])
        self.ctx_change_callback = None  # func()
        self._last_reload = None
        self.last_ctx = None
        # ui worker that fires off requests for UI update
        self._ui_updater_thread = None
        self._ui_updater_worker: Scheduler = None

        # settings
        self.config = None
        self.table_coloring_window = 60 * 30  # 30 mins
        self.merge_level: int = MergeLevel.NON_CONFLICTING
        self._auto_commit_enabled = auto_commit

        # command locks
        self.push_job_scheduler = Scheduler()
        self.sync_lock = threading.Lock()

        # create a pulling thread, but start on connection
        self._run_updater_threads = False
        self.user_states_update_thread = threading.Thread(target=self.updater_routine)

        # TODO: make the initialization of this with types of decompiler
        self.type_parser = BSTypeParser()
        if self.headless:
            self._init_headless_components()

    def _init_headless_components(self):
        pass

    @property
    def auto_commit_enabled(self):
        return self._auto_commit_enabled

    @auto_commit_enabled.setter
    def auto_commit_enabled(self, val):
        self.client.commit_on_update = val
        self._auto_commit_enabled = val

    @property
    def auto_push_enabled(self):
        return self.client.push_on_update if self.client is not None else True

    @auto_push_enabled.setter
    def auto_push_enabled(self, val):
        self.client.push_on_update = val

    @property
    def auto_pull_enabled(self):
        return self.client.pull_on_update if self.client is not None else True

    @auto_pull_enabled.setter
    def auto_pull_enabled(self, val):
        self.client.pull_on_update = val

    #
    #   Multithreading updaters, locks, and evaluators
    #

    def _init_ui_components(self):
        if self.headless:
            return

        # after this point you can import anything from UI and it is safe!
        from binsync.ui.qt_objects import (
            QThread
        )
        from binsync.ui.utils import BSUIScheduler
        # spawns a qthread/worker
        self._ui_updater_thread = QThread()
        self._ui_updater_worker = BSUIScheduler()
        self._ui_updater_worker.moveToThread(self._ui_updater_thread)
        self._ui_updater_thread.started.connect(self._ui_updater_worker.run)
        self._ui_updater_thread.finished.connect(self._ui_updater_thread.deleteLater)
        self._ui_updater_thread.start()

    def _stop_ui_components(self):
        if self.headless:
            return

        #stop the worker, quit the thread, wait for it to exit
        if self._ui_updater_worker and self._ui_updater_thread:
            self._ui_updater_worker.stop()
            self._ui_updater_thread.quit()
            _l.debug("Waiting for QThread ui_updater_thread to exit..")
            self._ui_updater_thread.wait()

    def schedule_job(self, cmd_func, *args, blocking=False, **kwargs):
        if not self._auto_commit_enabled:
            return None

        if blocking:
            return self.push_job_scheduler.schedule_and_wait_job(
                Job(cmd_func, *args, **kwargs),
                priority=SchedSpeed.FAST
            )

        self.push_job_scheduler.schedule_job(
            Job(cmd_func, *args, **kwargs),
            priority=SchedSpeed.FAST
        )
        return None

    def wait_for_next_push(self):
        last_push = self.client.last_push_attempt_time
        start_time = time.time()
        wait_time = 0
        while wait_time < self.reload_time:
            if last_push != self.client.last_push_attempt_time:
                if not self.push_job_scheduler._job_queue.empty():
                    # restart wait time when pusher still has jobs
                    start_time = time.time()
                else:
                    break

            time.sleep(BUSY_LOOP_COOLDOWN*2)
            wait_time = time.time() - start_time

    def updater_routine(self):
        while self._run_updater_threads:
            time.sleep(BUSY_LOOP_COOLDOWN)
            now = datetime.datetime.now(tz=datetime.timezone.utc)

            # validate a client is connected to this controller (which may be local only)
            if not self.check_client():
                continue

            # do git pull/push operations if a remote exist for the client
            if self.client.last_pull_attempt_time is None:
                self.client.update(commit_msg="User created")

            # update every reload_time
            elif int(now.timestamp() - self.client.last_pull_attempt_time.timestamp()) >= self.reload_time:
                self.client.update()
                
            if not self.headless:
                all_states = self.client.all_states()
                if not all_states:
                    _l.warning(f"There were no states remote or local.")
                    continue

                # update context knowledge every loop iteration
                if self.ctx_change_callback:
                    self._ui_updater_worker.schedule_job(
                        Job(self._check_and_notify_ctx, all_states)
                    )

                # update the control panel with new info every BINSYNC_RELOAD_TIME seconds
                if self._last_reload is None or \
                        int(now.timestamp() - self._last_reload.timestamp()) > self.reload_time:
                    self._last_reload = datetime.datetime.now(tz=datetime.timezone.utc)

                    self._ui_updater_worker.schedule_job(
                        Job(self._update_ui, all_states)
                    )

    def _update_ui(self, states):
        if not self.ui_callback:
            return

        self.ui_callback(states)

    def _check_and_notify_ctx(self, states):
        active_ctx = self.active_context()
        if active_ctx is None or self.last_ctx == active_ctx:
            return

        self.last_ctx = active_ctx
        self.ctx_change_callback(states)

    def start_worker_routines(self):
        self._run_updater_threads = True
        self.user_states_update_thread.daemon = True
        self.user_states_update_thread.start()

        self.push_job_scheduler.start_worker_thread()

        self._init_ui_components()

    def stop_worker_routines(self):
        self._run_updater_threads = False
        self.push_job_scheduler.stop_worker_thread()
        self._stop_ui_components()

    #
    # Client Interaction Functions
    #

    def connect(self, user, path, init_repo=False, remote_url=None, single_thread=False, **kwargs):
        binary_hash = self.binary_hash()
        self.client = Client(
            user, path, binary_hash, init_repo=init_repo, remote_url=remote_url, **kwargs
        )

        if not single_thread:
            self.start_worker_routines()

        return self.client.connection_warnings

    def check_client(self):
        return self.client is not None

    def status(self):
        if self.check_client():
            if self.client.has_remote and self.client.active_remote:
                return SyncControlStatus.CONNECTED
            return SyncControlStatus.CONNECTED_NO_REMOTE
        return SyncControlStatus.DISCONNECTED

    def status_string(self):
        stat = self.status()
        if stat == SyncControlStatus.CONNECTED:
            return f"<font color=#1eba06>{self.client.master_user}</font>"
        elif stat == SyncControlStatus.CONNECTED_NO_REMOTE:
            return f"<font color=#e7b416>{self.client.master_user}</font>"
        else:
            return "<font color=#cc3232>Disconnected</font>"

    def toggle_headless(self):
        self.headless = not self.headless

    @init_checker
    def users(self, priority=None, no_cache=True) -> Iterable[User]:  # TODO: fix no_cache user bug
        return self.client.users(priority=priority, no_cache=no_cache)

    def usernames(self, priority=None) -> Iterable[str]:
        for user in self.users(priority=priority):
            yield user.name

    #
    # Override Mandatory API:
    # These functions create a public API for things that hold a reference to the Controller from either another
    # thread or object. This is most useful for use in the UI, which can use this API to make general requests from
    # the decompiler regardless of internal decompiler API.
    #

    def binary_hash(self) -> str:
        """
        Returns a hex string of the currently loaded binary in the decompiler. For most cases,
        this will simply be a md5hash of the binary.

        @rtype: hex string
        """
        raise NotImplementedError

    def active_context(self) -> binsync.data.Function:
        """
        Returns an binsync Function. Currently only functions are supported as current contexts.
        This function will be called very frequently, so its important that its implementation is fast
        and can be done many times in the decompiler.
        """
        raise NotImplementedError

    def binary_path(self) -> Optional[str]:
        """
        Returns a string that is the path of the currently loaded binary. If there is no binary loaded
        then None should be returned.

        @rtype: path-like string (/path/to/binary)
        """
        raise NotImplementedError

    def get_func_size(self, func_addr) -> int:
        """
        Returns the size of a function

        @param func_addr:
        @return:
        """
        raise NotImplementedError

    def goto_address(self, func_addr) -> None:
        """
        Relocates decompiler display to provided address

        @param func_addr:
        @return:
        """
        raise NotImplementedError

    @property
    def decompiler_available(self) -> bool:
        """
        @return: True if decompiler is available for decompilation, False if otherwise
        """
        return True

    def save_native_decompiler_database(self):
        """
        Saves the current state of the decompilers database with the file name being the name of the current
        binary and the filename extension being that of the native decompilers save format
        """
        _l.info("Saving native decompiler database feature is not implemtened in this decompiler. Skipping...")

    def xrefs_to(self, artifact: Artifact) -> List[Artifact]:
        """
        Returns a list of artifacts that reference the provided artifact.
        @param artifact: Artifact to find references to
        @return: List of artifacts that reference the provided artifact
        """
        return []

    #
    # Optional Artifact API:
    # A series of functions that allow public access to live artifacts in the decompiler. As an example,
    # `function(addr)` will return the current Function at addr that the user would be seeing. This is useful
    # for having a common interface of reading data from other decompilers.
    #

    def functions(self) -> Dict[int, Function]:
        """
        Returns a dict of binsync.Functions that contain the addr, name, and size of each function in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    def function(self, addr, **kwargs) -> Optional[Function]:
        return None

    def global_vars(self) -> Dict[int, GlobalVariable]:
        """
        Returns a dict of binsync.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    def global_var(self, addr) -> Optional[GlobalVariable]:
        return None

    def structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of binsync.Structs that contain the name and size of each struct in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    def struct(self, name) -> Optional[Struct]:
        return None

    def enums(self) -> Dict[str, Enum]:
        """
        Returns a dict of binsync.Enum that contain the name of the enums in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    def enum(self, name) -> Optional[Enum]:
        return None

    def patches(self) -> Dict[int, Patch]:
        """
        Returns a dict of binsync.Patch that contain the addr of each Patch and the bytes.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    def patch(self, addr) -> Optional[Patch]:
        return None

    def global_artifacts(self):
        """
        Returns a light version of all artifacts that are global (non function associated):
        - structs, gvars, enums

        @return:
        """
        g_artifacts = {}
        for f in [self.structs, self.global_vars, self.enums]:
            g_artifacts.update(f())

        return g_artifacts

    def global_artifact(self, lookup_item: Union[str, int]):
        """
        Returns a live binsync.data version of the Artifact located at the lookup_item location, which can
        lookup any artifact supported in `global_artifacts`

        @param lookup_item:
        @return:
        """

        if isinstance(lookup_item, int):
            return self.global_var(lookup_item)
        elif isinstance(lookup_item, str):
            artifact = self.struct(lookup_item)
            if artifact:
                return artifact

            artifact = self.enum(lookup_item)
            return artifact

        return None

    def decompile(self, addr: int) -> Optional[str]:
        if not self.decompiler_available:
            return None

        # TODO: make this a function call after transitioning decompiler artifacts to LiveState
        for search_addr in (addr, self.artifact_lifer.lower_addr(addr)):
            func_found = False
            for func_addr, func in self.functions().items():
                if func.addr <= search_addr < (func.addr + func.size):
                    func_found = True
                    break
            else:
                func = None

            if func_found:
                break
        else:
            return None

        try:
            decompilation = self._decompile(func)
        except Exception as e:
            _l.warning(f"Failed to decompile function at {hex(addr)}: {e}")
            decompilation = None

        return decompilation

    def _decompile(self, function: Function) -> Optional[str]:
        return None

    #
    # Setters:
    # Work like Fillers, except can function without a BS Client. In effect, this allows you to
    # change the decompilers objects using BinSync objects.
    # TODO: all the code in this category set_* is experimental and not ready for production use
    # all this code should be implemented in the other decompilers or moved to a different project
    #

    def set_artifact(self, artifact: Artifact, lower=True, **kwargs) -> bool:
        """
        Sets a BinSync Artifact into the decompilers local database. This operations allows you to change
        what the native decompiler sees with BinSync Artifacts. This is different from opertions on a BinSync State,
        since this is native to the decompiler

        >>> func = Function(0xdeadbeef, 0x800)
        >>> func.name = "main"
        >>> controller.set_artifact(func)

        @param artifact:
        @param lower:       Wether to convert the Artifacts types and offset into the local decompilers format
        @return:            True if the Artifact was succesfuly set into the decompiler
        """
        set_map = {
            Function: self.set_function,
            FunctionHeader: self.set_function_header,
            StackVariable: self.set_stack_variable,
            Comment: self.set_comment,
            GlobalVariable: self.set_global_var,
            Struct: self.set_struct,
            Enum: self.set_enum,
            Patch: self.set_patch,
            Artifact: None,
        }

        if lower:
            artifact = self.lower_artifact(artifact)

        setter = set_map.get(type(artifact), None)
        if setter is None:
            _l.critical(f"Unsupported object is attempting to be set, please check your object: {artifact}")
            return False

        return setter(artifact, **kwargs)

    def set_function(self, func: Function, **kwargs) -> bool:
        update = False
        header = func.header
        if header is not None:
            update = self.set_function_header(header, **kwargs)

        if func.stack_vars:
            for variable in func.stack_vars.values():
                update |= self.set_stack_variable(variable, **kwargs)

        return update

    def set_function_header(self, fheader: FunctionHeader, **kwargs) -> bool:
        return False

    def set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        return False

    def set_comment(self, comment: Comment, **kwargs) -> bool:
        return False

    def set_global_var(self, gvar: GlobalVariable, **kwargs) -> bool:
        return False

    def set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        return False

    def set_enum(self, enum: Enum, **kwargs) -> bool:
        return False

    def set_patch(self, path: Patch, **kwargs) -> bool:
        return False

    #
    # Change Callback API
    # TODO: all the code in this category on_* is experimental and not ready for production use
    # all this code should be implemented in the other decompilers or moved to a different project
    #

    def on_function_header_changed(self, fheader: FunctionHeader):
        pass

    def on_stack_variable_changed(self, svar: StackVariable):
        pass

    def on_comment_changed(self, comment: Comment):
        pass

    def on_struct_changed(self, struct: Struct):
        pass

    def on_enum_changed(self, enum: Enum):
        pass

    def on_global_variable_changed(self, gvar: GlobalVariable):
        pass

    #
    # Client API & Shortcuts
    #

    def lift_artifact(self, artifact: Artifact) -> Artifact:
        return self.artifact_lifer.lift(artifact)

    def lower_artifact(self, artifact: Artifact) -> Artifact:
        return self.artifact_lifer.lower(artifact)

    @init_checker
    def get_state(self, user=None, version=None, priority=None, no_cache=False) -> State:
        return self.client.get_state(user=user, version=version, priority=priority, no_cache=no_cache)

    @init_checker
    def pull_artifact(self, type_: Artifact, *identifiers, many=False, user=None, state=None) -> Optional[Artifact]:
        try:
            get_artifact_func = self.ARTIFACT_GET_MAP[type_] if not many else self.ARTIFACT_GET_MAP[(type_, GET_MANY)]
        except KeyError:
            _l.info(f"Attempting to pull an unsupported Artifact of type {type_} with {identifiers}")
            return None

        # assure a state exists
        if not state:
            state = self.get_state(user=user)

        try:
            artifact = get_artifact_func(state, *identifiers)
        except Exception:
            _l.warning(f"Failed to pull an supported Artifact of type {type_} with {identifiers}")
            return None

        if not artifact:
            return artifact

        return self.lower_artifact(artifact)

    @init_checker
    def push_artifact(self, artifact: Artifact, user=None, state=None, commit_msg=None, set_last_change=True, make_func=True, **kwargs) -> bool:
        """
        Every pusher artifact does three things
        1. Get the state setter function based on the class of the Obj
        2. Get the commit msg of the obj based on the class
        3. Lift the obj based on the Controller lifters

        @param artifact:
        @param user:
        @param state:
        @return:
        """
        _l.debug(f"Running push now for {artifact}")
        if not artifact:
            return False

        try:
            set_artifact_func = self.ARTIFACT_SET_MAP[artifact.__class__]
        except KeyError:
            _l.info(f"Attempting to push an unsupported Artifact of type {artifact}")
            return False

        # assure state exists
        if not state:
            state = self.get_state(user=user)
        if not state or not isinstance(state, State):
            _l.critical("Failed to get a state for push {artifact}, this is likely due to network error. Report me if back trace!")
            return False

        # assure function existence for artifacts requiring a function
        if isinstance(artifact, (FunctionHeader, StackVariable, Comment)) and make_func:
            func_addr = artifact.func_addr if hasattr(artifact, "func_addr") else artifact.addr
            if func_addr and not state.get_function(func_addr):
                self.push_artifact(Function(func_addr, self.get_func_size(func_addr)), state=state, set_last_change=set_last_change)

        # lift artifact into standard BinSync format
        artifact = self.lift_artifact(artifact)

        # set the artifact in the target state, likely master
        _l.debug(f"Setting an artifact now into {state} as {artifact}")
        was_set = set_artifact_func(state, artifact, set_last_change=set_last_change, **kwargs)

        # TODO: make was_set reliable
        _l.debug(f"{state} committing now with {commit_msg or artifact.commit_msg}")
        self.client.commit_state(state, msg=commit_msg or artifact.commit_msg)

        return was_set

    #
    # Fillers:
    # A filler function is generally responsible for pulling down data from a specific user state
    # and reflecting those changes in decompiler view (like the text on the screen). Normally, these changes
    # will also be accompanied by a Git commit to the master users state to save the changes from pull and
    # fill into their BS database. In special cases, a filler may only update the decompiler UI but not directly
    # cause a save of the BS state.
    #

    def fill_event_handler(self, filler_func, *identifiers,
                           artifact=None, user=None, state=None, master_state=None, merge_level=None, blocking=False,
                           commit_msg=None,
                           **kwargs
                           ):
        """
        fill_event_handler is the function called before every `fill_<artifact>` function. This handler is responsible
        for assuring a variety of things exist for subsequent call to `fill_<artifact>`.

        @param filler_func:
        @param identifiers:
        @param artifact:
        @param user:
        @param state:
        @param master_state:
        @param merge_level:
        @param blocking:
        @param kwargs:
        @return:
        """

        ARTIFACT_FILL_MAP = {
            self.fill_function.__name__: Function,
            self.fill_function_header.__name__: FunctionHeader,
            self.fill_stack_variable.__name__: StackVariable,
            self.fill_comment.__name__: Comment,
            self.fill_global_var.__name__: GlobalVariable,
            self.fill_struct.__name__: Struct,
            self.fill_enum.__name__: Enum
        }

        state = state if state is not None else self.get_state(user=user, priority=SchedSpeed.FAST)
        master_state = master_state if master_state is not None else self.get_state(priority=SchedSpeed.FAST)
        artifact_type = ARTIFACT_FILL_MAP.get(filler_func.__name__, None)
        if not artifact_type:
            _l.warning(f"Attempting to Fill an unknown type! Stopping Fill...")
            return None

        art_getter = self.ARTIFACT_GET_MAP.get(artifact_type)
        master_artifact = artifact if artifact else self.lower_artifact(art_getter(master_state, *identifiers))
        merged_artifact = self.merge_artifacts(
            master_artifact,  self.lower_artifact(art_getter(state, *identifiers)),
            merge_level=merge_level, master_state=master_state
        )
        merged_artifact.last_change = None

        lock = self.sync_lock if not self.sync_lock.locked() else FakeSyncLock()
        with lock:
            try:
                fill_changes = filler_func(
                    self,
                    *identifiers,
                    artifact=merged_artifact, user=user, state=state, master_state=master_state, merge_level=merge_level,
                    **kwargs
                )
            except Exception as e:
                fill_changes = False
                _l.error(f"Failed to fill artifact {merged_artifact} because of an error {e}")


        _l.info(
            f"Successfully synced new changes from {state.user} for {merged_artifact}" if fill_changes
            else f"No new changes or failed to sync from {state.user} for {merged_artifact}"
        )

        if blocking:
            self.push_artifact(merged_artifact, state=master_state, set_last_change=False, commit_msg=commit_msg)
        else:
            self.schedule_job(
                self.push_artifact,
                merged_artifact,
                state=master_state,
                set_last_change=False,
                commit_msg=commit_msg
            )

        return fill_changes

    @fill_event
    def fill_struct(self, struct_name, header=True, members=True, artifact=None, **kwargs):
        """

        @param struct_name:
        @param user:
        @param state:
        @param header:
        @param members:
        @return:
        """
        _l.debug(f"Fill Struct is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        """
        Grab a global variable for a specified address and fill it locally

        @param var_addr:
        @param user:
        @param state:
        @return:
        """
        _l.debug(f"Fill Global Var is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_enum(self, enum_name, user=None, artifact=None, **kwargs):
        """
        Grab an enum and fill it locally

        @param enum_name:
        @param user:
        @param state:
        @return:
        """
        _l.debug(f"Fill Enum is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_stack_variable(self, func_addr, offset, user=None, artifact=None, **kwargs):
        _l.debug(f"Fill Stack Var is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_function_header(self, func_addr, user=None, artifact=None, **kwargs):
        _l.debug(f"Fill Function Header is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_comment(self, addr, user=None, artifact=None, **kwargs):
        _l.debug(f"Fill Comments is not implemented in your decompiler.")
        return False

    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        """
        Grab all relevant information from the specified user and fill the @func_addr.
        """
        dec_func: Function = self.function(func_addr, **kwargs)
        if not dec_func:
            _l.warning(f"The function at {hex(func_addr)} does not exist in your decompiler.")
            dec_func = Function(None, None)

        master_func: Function = artifact
        changes = False

        # function header
        if master_func.header and master_func.header != dec_func.header:
            # type is user made (a struct)
            changes |= self.import_user_defined_type(master_func.header.type, **kwargs)
            changes |= self.fill_function_header(func_addr, artifact=master_func.header, **kwargs)

        # stack vars
        if master_func.stack_vars and master_func.stack_vars != dec_func.stack_vars:
            for offset, sv in master_func.stack_vars.items():
                dec_sv = dec_func.stack_vars.get(offset, None)
                if not dec_sv:
                    _l.warning(f"Decompiler stack var not found at {offset}")

                if dec_sv == sv:
                    continue

                corrected_off = dec_sv.offset if dec_sv and dec_sv.offset else sv.offset
                changes |= self.import_user_defined_type(sv.type, **kwargs)
                changes |= self.fill_stack_variable(func_addr, corrected_off, artifact=sv, **kwargs)

        # comments
        for addr, cmt in kwargs['state'].get_func_comments(func_addr).items():
            changes |= self.fill_comment(addr, artifact=cmt, **kwargs)

        return changes

    def fill_functions(self, user=None, **kwargs):
        change = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for addr, func in state.functions.items():
            change |= self.fill_function(addr, state=state, master_state=master_state)

        return change

    def fill_structs(self, user=None, **kwargs):
        """
        Grab all the structs from a specified user, then fill them locally

        @param user:
        @param state:
        @return:
        """
        changes = False
        # only do struct headers for circular references
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, struct in state.structs.items():
            changes |= self.fill_struct(name, user=user, state=state, master_state=master_state, members=False)

        for name, struct in state.structs.items():
            changes |= self.fill_struct(name, user=user, state=state, master_state=master_state, header=False)

        return changes

    def fill_enums(self, user=None, **kwargs):
        """
        Grab all enums and fill it locally

        @param user:
        @param state:
        @return:
        """
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, enum in state.enums.items():
            changes |= self.fill_enum(name, user=user, state=state, master_state=master_state)

        return changes

    def fill_global_vars(self, user=None, **kwargs):
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for off, gvar in state.global_vars.items():
            changes |= self.fill_global_var(off, user=user, state=state, master_state=master_state)

        return changes

    def fill_all(self, user=None, **kwargs):
        """
        Connected to the Sync All action:
        syncs in all the data from the targeted user

        @param user:
        @param state:
        @return:
        """
        _l.info(f"Filling all data from user {user}...")

        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        fillers = [
            self.fill_structs, self.fill_enums, self.fill_global_vars, self.fill_functions
        ]

        changes = False
        for filler in fillers:
            changes |= filler(user=user, state=state, master_state=master_state)

        return changes

    @init_checker
    def magic_fill(self, preference_user=None, target_artifacts=None):
        """
        Traverses all the data in the BinSync repo, starting with an optional preference user,
        and sequentially merges that data together in a non-conflicting way. This also means that the prefrence
        user makes up the majority of the initial data you sync in.

        This process supports: functions (header, stack vars), structs, and global vars
        TODO:
        - support for enums
        - refactor fill_function to stop attempting to set master state after we do
        -

        @param preference_user:
        @param target_artifacts:
        @return:
        """
        _l.info(f"Staring a Magic Sync with a preference for {preference_user}")
        self.save_native_decompiler_database()

        if self.merge_level == MergeLevel.OVERWRITE:
            _l.warning(f"Using Magic Sync with OVERWRITE is not supported, switching to NON-CONFLICTING")

        # re-order users for the prefered user to be at the front of the queue (if they exist)
        all_users = list(self.usernames(priority=SchedSpeed.FAST))
        preference_user = preference_user if preference_user else self.client.master_user
        master_state = self.client.get_state(user=self.client.master_user, priority=SchedSpeed.FAST)
        users_state_map = {
            user: self.get_state(user=user, priority=SchedSpeed.FAST)
            for user in all_users
        }
        all_users.remove(preference_user)

        # TODO: make structus work in IDA
        target_artifacts = target_artifacts or {
            #Struct: self.fill_struct,
            Comment: lambda *x, **y: None,
            Function: self.fill_function,
            GlobalVariable: self.fill_global_var,
            Enum: self.fill_enum
        }

        for artifact_type, filler_func in target_artifacts.items():
            _l.info(f"Magic Syncing artifacts of type {artifact_type.__name__} now...")
            pref_state = users_state_map[preference_user]
            for identifier in self.changed_artifacts_of_type(artifact_type, users=all_users + [preference_user], states=users_state_map):
                pref_art = self.pull_artifact(artifact_type, identifier, state=pref_state)
                for user in all_users:
                    user_state = users_state_map[user]
                    user_art = self.pull_artifact(artifact_type, identifier, state=user_state)

                    if not user_art:
                        continue

                    if not pref_art:
                        pref_art = user_art.copy()

                    pref_art = pref_art.nonconflict_merge(user_art)
                    pref_art.last_change = None

                _l.debug(f"Filling artifact {pref_art} now...")
                try:
                    filler_func(
                        identifier, artifact=pref_art, state=master_state,  commit_msg=f"Magic Synced {pref_art}",
                        merge_level=MergeLevel.NON_CONFLICTING
                    )
                except Exception as e:
                    _l.info(f"Banishing exception: {e}")

        _l.info(f"Magic Syncing Completed!")

    #
    # Force Push
    #

    @init_checker
    def force_push_functions(self, func_addrs: List[int]):
        """
        Collects the functions currently stored in the decompiler, not the BS State, and commits it to
        the master users BS Database.

        TODO: push the comments and custom types that are associated with each stack vars
        TODO: refactor to use internal push_function for correct commit message
        """
        funcs = {}
        for func_addr in progress_bar(func_addrs, gui=not self.headless, desc="Decompiling functions to push..."):
            f = self.function(func_addr)
            if not f:
                _l.warning(f"Failed to force push function @ {func_addr:#0x}")
                continue

            funcs[func_addr] = f

        _l.info(f"Scheduling {len(funcs)} functions to be pushed...")
        master_state: State = self.client.get_state(priority=SchedSpeed.FAST)

        for func_addr, func_obj in progress_bar(funcs.items(), gui=not self.headless, desc="Scheduling functions to push..."):
            self.schedule_job(
                self.push_artifact,
                func_obj,
                state=master_state,
                commit_msg=f"Forced pushed function {func_addr:#0x}",
                priority=SchedSpeed.FAST
            )

        _l.info("All functions scheduled to be pushed!")


    @init_checker
    def force_push_global_artifacts(self, lookup_items: List):
        """
        Collects the global artifact (struct, gvar, enum) currently stored in the decompiler, not the BS State,
        and commits it to the master users BS Database.

        @param lookup_item:
        @return: Success of committing the Artifact
        """
        if self.headless:
            _l.critical("Force push is currently not supported headlessly.")
            return


        master_state: State = self.client.get_state(priority=SchedSpeed.FAST)
        for lookup_item in lookup_items:
            _l.info(f"Attempting to sync {lookup_item}")
            global_art = self.global_artifact(lookup_item)
            _l.info(f"Global artifact lookup result: {global_art}")
            if not global_art:
                continue
            global_art = self.artifact_lifer.lift(global_art)
            _l.info(f"POST LIFTING: {global_art}")
            self.schedule_job(
                self.push_artifact,
                global_art,
                state=master_state,
                commit_msg=f"Forced pushed global {global_art}",
                priority=SchedSpeed.FAST
            )
            _l.info(f"Pushed global {global_art}")

    #
    # Utils
    #

    def merge_artifacts(self, art1: Artifact, art2: Artifact, merge_level=None, **kwargs):
        if merge_level is None:
            merge_level = self.merge_level

        if art2 is None:
            return art1.copy()

        if merge_level == MergeLevel.OVERWRITE or (not art1) or (art1 == art2):
            return art2.copy() if art2 else None

        if merge_level == MergeLevel.NON_CONFLICTING:
            merge_art = art1.nonconflict_merge(art2, **kwargs)

        elif merge_level == MergeLevel.MERGE:
            _l.warning("Manual Merging is not currently supported, using non-conflict syncing...")
            merge_art = art1.nonconflict_merge(art2, **kwargs)

        else:
            raise Exception("Your BinSync Client has an unsupported Sync Level activated")

        return merge_art

    def changed_artifacts_of_type(self, type_: Artifact, users=[], states={}):
        prop_map = {
            Function: "functions",
            Comment: "comments",
            GlobalVariable: "global_vars",
            Struct: "structs",
            Enum: "enums"
        }

        try:
            prop_name = prop_map[type_]
        except KeyError:
            _l.warning(f"Attempted to get changed artifacts of type {type_} which is unsupported")
            return set()

        known_arts = set()
        for username in users:
            state = states[username]
            artifact_dict: Dict = getattr(state, prop_name)
            for identifier in artifact_dict:
                known_arts.add(identifier)

        return known_arts

    def type_is_user_defined(self, type_str, state=None):
        if not type_str:
            return None

        type_: BSType = self.type_parser.parse_type(type_str)
        if not type_:
            # it was not parseable
            return None

        # type is known and parseable
        if not type_.is_unknown:
            return None

        base_type_str = type_.base_type.type
        return base_type_str if base_type_str in state.structs.keys() else None

    def import_user_defined_type(self, type_str, **kwargs):
        state = kwargs.pop('state')
        master_state = kwargs['master_state']
        base_type_str = self.type_is_user_defined(type_str, state=state)
        if not base_type_str:
            return False

        struct: Struct = state.get_struct(base_type_str)
        if not struct:
            return False

        nested_undefined_structs = False
        for off, memb in struct.members.items():
            user_type = self.type_is_user_defined(memb.type, state=state)
            if user_type and user_type not in master_state.structs.keys():
                # should we ever happen to have a struct with a nested type that is
                # also a struct that we don't have in our master_state, then we give up
                # and attempt to fill all structs to resolve type issues
                nested_undefined_structs = True
                _l.info(f"Nested undefined structs detected, pulling all structs from {state.user}")
                break

        changes = self.fill_struct(base_type_str, state=state, **kwargs) if not nested_undefined_structs \
            else self.fill_structs(state=state, **kwargs)
        return changes

    def get_master_and_user_state(self, user=None, **kwargs):
        state = kwargs.get("state", None) \
            or self.get_state(user=user, priority=SchedSpeed.FAST)

        master_state = kwargs.get("master_state", None) \
            or self.get_state(priority=SchedSpeed.FAST)

        return master_state, state

    #
    # Config Utils
    #

    def load_saved_config(self):
        config = ProjectConfig.load_from_file(self.binary_path() or "")
        if not config:
            return
        self.config = config
        _l.info(f"Loaded configuration file: '{self.config.path}'")

        self.config = config
        self.table_coloring_window = self.config.table_coloring_window or self.table_coloring_window
        self.merge_level = self.config.merge_level or self.merge_level

        if self.config.log_level == "debug":
            logging.getLogger("binsync").setLevel("DEBUG")
            logging.getLogger("ida_binsync").setLevel("DEBUG")

        else:
            logging.getLogger("binsync").setLevel("INFO")
            logging.getLogger("ida_binsync").setLevel("INFO")

        return self.config



