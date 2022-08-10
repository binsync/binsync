import logging
import threading
import time
from collections import OrderedDict, defaultdict
from functools import wraps
from typing import Dict, Iterable, List, Optional, Union

import binsync.data
from binsync.common.artifact_lifter import ArtifactLifter
from binsync.core.client import Client, SchedSpeed, Scheduler, Job
from binsync.data.type_parser import BSTypeParser, BSType
from binsync.data import (
    State, User, Artifact,
    Function, FunctionHeader, FunctionArgument, StackVariable,
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
    def _fill_event(self: "BinSyncController", *args, **kwargs):
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

class BinSyncController:

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
    def __init__(self, artifact_lifter=None, headless=False, reload_time=10):
        self.headless = headless
        self.reload_time = reload_time
        self.artifact_lifer: ArtifactLifter = artifact_lifter

        # client created on connection
        self.client = None  # type: Optional[Client]

        # ui callback created on UI init
        self.ui_callback = None  # func()
        self.ctx_change_callback = None  # func()
        self._last_reload = None
        self.last_ctx = None

        # settings
        self.merge_level: int = MergeLevel.NON_CONFLICTING

        # command locks
        self.job_scheduler = Scheduler()
        self.sync_lock = threading.Lock()

        # create a pulling thread, but start on connection
        self.updater_thread = threading.Thread(target=self.updater_routine)
        self._run_updater_threads = False

        # TODO: make the initialization of this with types of decompiler
        self.type_parser = BSTypeParser()

    #
    #   Multithreading updaters, locks, and evaluators
    #

    def schedule_job(self, cmd_func, *args, blocking=False, **kwargs):
        if blocking:
            return self.job_scheduler.schedule_and_wait_job(
                Job(cmd_func, *args, **kwargs)
            )

        self.job_scheduler.schedule_job(
            Job(cmd_func, *args, **kwargs)
        )
        return None

    def updater_routine(self):
        while self._run_updater_threads:
            time.sleep(BUSY_LOOP_COOLDOWN)

            # validate a client is connected to this controller (may not have remote )
            if not self.check_client():
                continue

            # do git pull/push operations if a remote exist for the client
            if self.client.last_pull_attempt_ts is None:
                self.client.update(commit_msg="User created")

            # update every reload_time
            elif time.time() - self.client.last_pull_attempt_ts > self.reload_time:
                self.client.update()

            if not self.headless:
                # update context knowledge every loop iteration
                if self.ctx_change_callback:
                    self._check_and_notify_ctx()

                # update the control panel with new info every BINSYNC_RELOAD_TIME seconds
                if self._last_reload is None or \
                        time.time() - self._last_reload > self.reload_time:
                    self._last_reload = time.time()
                    self._update_ui()

    def _update_ui(self):
        if not self.ui_callback:
            return

        self.ui_callback()

    def _check_and_notify_ctx(self):
        active_ctx = self.active_context()
        if active_ctx is None or self.last_ctx == active_ctx:
            return

        self.last_ctx = active_ctx
        self.ctx_change_callback()

    def start_worker_routines(self):
        self._run_updater_threads = True
        self.updater_thread.setDaemon(True)
        self.updater_thread.start()

        self.job_scheduler.start_worker_thread()

    def stop_worker_routines(self):
        self._run_updater_threads = False
        self.job_scheduler.stop_worker_thread()

    #
    # Client Interaction Functions
    #

    def connect(self, user, path, init_repo=False, remote_url=None):
        binary_hash = self.binary_hash()
        self.client = Client(
            user, path, binary_hash, init_repo=init_repo, remote_url=remote_url
        )

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
    def users(self, priority=None) -> Iterable[User]:
        return self.client.users(priority=priority)

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

    def function(self, addr) -> Optional[Function]:
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
    def push_artifact(self, artifact: Artifact, user=None, state=None, commit_msg=None, set_last_change=True, **kwargs) -> bool:
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

        # assure function existence for artifacts requiring a function
        if isinstance(artifact, (FunctionHeader, StackVariable, Comment)):
            func_addr = artifact.func_addr if hasattr(artifact, "func_addr") else artifact.addr
            if func_addr and not state.get_function(func_addr):
                self.push_artifact(Function(func_addr, self.get_func_size(func_addr)), state=state, set_last_change=set_last_change)

        # lift artifact into standard BinSync format
        artifact = self.lift_artifact(artifact)

        # set the artifact in the target state, likely master
        _l.debug(f"Setting an artifact now into {state} as {artifact}")
        was_set = set_artifact_func(state, artifact, set_last_change=set_last_change)

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

        lock = self.sync_lock if not self.sync_lock.locked() else FakeSyncLock()
        with lock:
            fill_changes = filler_func(
                self,
                *identifiers,
                artifact=merged_artifact, user=user, state=state, master_state=master_state, merge_level=merge_level,
                **kwargs
            )

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


    @init_checker
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

    @init_checker
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


    @init_checker
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

    @init_checker
    @fill_event
    def fill_function(self, func_addr, user=None, artifact=None, **kwargs):
        """
        Grab all relevant information from the specified user and fill the @func_addr.
        """
        dec_func: Function = self.function(func_addr)
        if not dec_func:
            _l.warning(f"The function at {hex(func_addr)} does not exist in your decompiler. Stopping sync.")
            return False

        master_func: Function = artifact
        changes = False

        # function header
        if master_func.header and master_func.header != dec_func.header:
            # type is user made (a struct)
            changes |= self.import_user_defined_type(master_func.header.ret_type, **kwargs)
            changes |= self.fill_function_header(func_addr, artifact=master_func.header, **kwargs)

        # stack vars
        if master_func.stack_vars and master_func.stack_vars != dec_func.stack_vars:
            for offset, sv in master_func.stack_vars.items():
                dec_sv = dec_func.stack_vars.get(offset, None)
                if not dec_sv or sv == dec_sv:
                    _l.info(f"Decompiler stack var not found at {offset}")
                    continue

                changes |= self.import_user_defined_type(sv.type, **kwargs)
                print(f"Doing a fill now for {sv}")
                changes |= self.fill_stack_variable(func_addr, dec_sv.stack_offset, artifact=sv, **kwargs)

        # comments
        for addr, cmt in kwargs['state'].get_func_comments(func_addr).items():
            changes |= self.fill_comment(addr, artifact=cmt, **kwargs)

        return changes

    @init_checker
    def fill_functions(self, user=None, **kwargs):
        change = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for addr, func in state.functions.items():
            change |= self.fill_function(addr, state=state, master_state=master_state)

        return change

    @init_checker
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

    @init_checker
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

    @init_checker
    def fill_global_vars(self, user=None, **kwargs):
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for off, gvar in state.global_vars.items():
            changes |= self.fill_global_var(off, user=user, state=state, master_state=master_state)

        return changes

    @init_checker
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
        # re-order users for the prefered user to be at the front of the queue (if they exist)
        all_users = list(self.usernames(priority=SchedSpeed.FAST))
        preference_user = preference_user if preference_user else self.client.master_user
        master_state = self.client.get_state(user=self.client.master_user, priority=SchedSpeed.FAST)
        users_state_map = {
            user: self.get_state(user=user, priority=SchedSpeed.FAST)
            for user in all_users
        }
        all_users.remove(preference_user)

        target_artifacts = target_artifacts or {
            Struct: self.fill_struct,
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

                filler_func(identifier, artifact=pref_art, state=master_state,  commit_msg=f"Magic Synced {pref_art}")

        _l.info(f"Magic Syncing Completed!")

    #
    # Force Push
    #

    @init_checker
    def force_push_function(self, addr: int) -> bool:
        """
        Collects the function currently stored in the decompiler, not the BS State, and commits it to
        the master users BS Database.

        TODO: push the comments and custom types that are associated with each stack var
        TODO: refactor to use internal push_function for correct commit message

        @param addr:
        @return: Success of committing the Function
        """
        func = self.function(addr)
        if not func:
            _l.info(f"Pushing function {hex(addr)} Failed")
            return False

        master_state: State = self.client.get_state(priority=SchedSpeed.FAST)
        pushed = self.push_artifact(func, state=master_state, commit_msg=f"Forced pushed function {func}")
        return pushed


    @init_checker
    def force_push_global_artifact(self, lookup_item):
        """
        Collects the global artifact (struct, gvar, enum) currently stored in the decompiler, not the BS State,
        and commits it to the master users BS Database.

        @param lookup_item:
        @return: Success of committing the Artifact
        """
        global_art = self.global_artifact(lookup_item)
        
        if not global_art:
            _l.info(f"Pushing global artifact {lookup_item if isinstance(lookup_item, str) else hex(lookup_item)} Failed")
            return False

        master_state: State = self.client.get_state(priority=SchedSpeed.FAST)
        global_art = self.artifact_lifer.lift(global_art)
        pushed = self.push_artifact(global_art, state=master_state, commit_msg=f"Force pushed {global_art}")
        return pushed

    #
    # Utils
    #

    def merge_artifacts(self, art1: Artifact, art2: Artifact, merge_level=None, **kwargs):
        if merge_level is None:
            merge_level = self.merge_level

        if merge_level == MergeLevel.OVERWRITE or not art1 or art1 == art2:
            return art2

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

        base_type_str = type_.base_type.type_str
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
        for off, memb in struct.struct_members.items():
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
