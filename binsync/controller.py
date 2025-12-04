import logging
import threading
import datetime
import time
from collections import defaultdict
from functools import wraps
from typing import Dict, Iterable, Optional, Union, List, Tuple
import math
import re

from libbs.api.utils import progress_bar
from libbs.artifacts import (
    Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct, FunctionArgument, StructMember, Typedef, Segment, Context
)
from libbs.api import DecompilerInterface
from libbs.api.type_parser import CType

from binsync.core.client import Client, SchedSpeed, Scheduler, Job
from binsync.core.state import State
from binsync.core.user import User
from binsync.configuration import BinSyncBSConfig

from wordfreq import word_frequency

from libbs.decompilers import IDA_DECOMPILER

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
    LOADING = 3


class MergeLevel:
    OVERWRITE = 0
    NON_CONFLICTING = 1
    MERGE = 2


#
#   Controller
#

class BSController:
    """
    The BinSync Controller is the main interface for syncing with the BinSync Client which preforms git tasks
    such as pull and push. In the Controller higher-level tasks are done such as updating UI with changes
    and preforming syncs and pushes on data users need/change.

    All class properties that have a "= None" means they must be set during runtime by an outside process.
    The client will be set on connection. The ctx_change_callback will be set by an outside UI

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
        Typedef: State.get_typedef,
        (Typedef, GET_MANY): State.get_typedefs,
        Segment: State.get_segment,
        (Segment, GET_MANY): State.get_segments
    }

    DEFAULT_SEMAPHORE_SIZE = 100

    def __init__(
        self, decompiler_interface: DecompilerInterface = None, headless=False, auto_commit=True, reload_time=10,
        do_safe_sync_all=False, **kwargs
    ):
        self.headless = headless
        self.reload_time = reload_time
        if decompiler_interface is None:
            self.deci = DecompilerInterface.discover(thread_artifact_callbacks=False)
        else:
            self.deci = decompiler_interface

        # command locks
        self.push_job_scheduler = Scheduler(name="PushJobScheduler")
        self.sync_semaphore = threading.Semaphore(value=self.DEFAULT_SEMAPHORE_SIZE)

        # never do callbacks while we are syncing data
        self.deci.should_watch_artifacts = self.should_watch_artifacts
        # callbacks for changes to artifacts
        for typ in self.CHANGE_WATCHERS:
            self.deci.artifact_change_callbacks[typ].append(self._commit_hook_based_changes)

        # record movements (in IDA) and use that for discovering auto-created objects
        self.recorded_movements = []
        self.startup_time = None
        if self.deci.name == IDA_DECOMPILER:
            self.deci.force_click_recording = True
            self.deci.artifact_change_callbacks[Context].append(self._handle_context_update)

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

        # client created on connection
        self.client = None  # type: Optional[Client]

        # ui callback created on UI init
        self.ui_callback = None  # func(states: List[State])
        self.ctx_change_callback = None  # func()
        self._last_reload = None
        self.last_active_func = None
        self._got_first_state = False
        # ui worker that fires off requests for UI update
        self._ui_updater_thread = None
        self._ui_updater_worker: Scheduler = None

        # settings
        self.config = None
        self.table_coloring_window = 60 * 30  # 30 mins
        self.merge_level: int = MergeLevel.NON_CONFLICTING
        self._auto_commit_enabled = auto_commit

        # create a pulling thread, but start on connection
        self._run_updater_threads = False
        self.user_states_update_thread = threading.Thread(target=self.updater_routine, daemon=True)

        # other properties
        self.progress_view_open = False
        self.do_safe_sync_all = do_safe_sync_all
        self.safe_synced_users = {}
        self.precise_diff_preview = False

        if self.headless:
            self._init_headless_components()

    def _init_headless_components(self):
        pass

    def shutdown(self):
        self.stop_worker_routines()
        self.deci.shutdown()

    #
    # Git Properties
    #

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
    # Multithreading updaters, locks, and evaluators
    #

    def should_watch_artifacts(self):
        return bool(self.check_client() and self.is_not_syncing_data())

    def _init_ui_components(self):
        if self.headless:
            return

        # after this point you can import anything from UI and it is safe!
        from libbs.ui.qt_objects import (
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

        # stop the worker, quit the thread, wait for it to exit
        if self._ui_updater_worker and self._ui_updater_thread:
            self._ui_updater_worker.stop()
            self._ui_updater_thread.quit()
            _l.debug("Waiting for QThread ui_updater_thread to exit..")
            # TODO: on MacOS IDA Pro 8 >, this will hang the process, so we force the timeout after 5 seconds
            #   this still causes a bad message for IDA Pro on Mac
            self._ui_updater_thread.wait(2000)

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

            time.sleep(BUSY_LOOP_COOLDOWN * 2)
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
                _l.debug("Attempting to update states now")
                self.client.commit_and_update_states(commit_msg="User created")

            # update every reload_time
            elif int(now.timestamp() - self.client.last_pull_attempt_time.timestamp()) >= self.reload_time:
                self.client.commit_and_update_states()

            if not self.headless:
                all_states = self.client.all_states()
                if not all_states:
                    _l.warning("There were no states remote or local.")
                    continue

                self._got_first_state |= True
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

                    # attempt to fast-sync anything that is easy to sync
                    if self.do_safe_sync_all:
                        self.safe_sync_all(all_states)


    def _update_ui(self, states):
        if not self.ui_callback:
            return

        self.ui_callback(states)

    def _check_and_notify_ctx(self, states):
        active_ctx = self.deci.gui_active_context()
        if (
            # no active context
            active_ctx is None or
            # no function in active context (not supported in binsync)
            active_ctx.func_addr is None or
            # no change in active context func
            (self.last_active_func is not None and active_ctx.func_addr == self.last_active_func.addr)
        ):
            return

        curr_func = self.deci.fast_get_function(active_ctx.func_addr)
        self.last_active_func = curr_func
        self.ctx_change_callback(states)

    def start_worker_routines(self):
        self._run_updater_threads = True
        self.user_states_update_thread.start()

        self.push_job_scheduler.start_worker_thread()

        self._init_ui_components()
        # start the callbacks for edits to artifacts
        self.deci.start_artifact_watchers()

    def stop_worker_routines(self):
        self._run_updater_threads = False
        self.push_job_scheduler.stop_worker_thread()
        self._stop_ui_components()

    #
    # Client Interaction Functions
    #

    def connect(self, user, path, init_repo=False, remote_url=None, single_thread=False, **kwargs):
        binary_hash = self.deci.binary_hash
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
                return SyncControlStatus.CONNECTED if self._got_first_state else SyncControlStatus.LOADING
            return SyncControlStatus.CONNECTED_NO_REMOTE
        return SyncControlStatus.DISCONNECTED

    def status_string(self):
        stat = self.status()
        if stat == SyncControlStatus.CONNECTED:
            return f"<font color=#1eba06>{self.client.master_user}</font>"
        elif stat == SyncControlStatus.CONNECTED_NO_REMOTE:
            return f"<font color=#e7b416>{self.client.master_user}</font>"
        elif stat == SyncControlStatus.LOADING:
            return f"<font color=#ffa500>Loading...</font>"
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

    def save_native_decompiler_database(self):
        """
        TODO: find out how to replace this func

        Saves the current state of the interface_overrides database with the file name being the name of the current
        binary and the filename extension being that of the native interface_overrides save format
        """
        _l.info("Saving native decompiler database feature is not implemtened in this decompiler. Skipping...")

    #
    # Client API & Shortcuts
    #

    @init_checker
    def get_state(self, user=None, priority=None, no_cache=False) -> State:
        return self.client.get_state(user=user, priority=priority, no_cache=no_cache)

    @init_checker
    def pull_artifact(self, type_: Artifact, *identifiers, many=False, user=None, state=None) -> Optional[Artifact]:
        try:
            get_artifact_func = self.ARTIFACT_GET_MAP[type_] if not many else self.ARTIFACT_GET_MAP[(type_, GET_MANY)]
        except KeyError:
            _l.info("Attempting to pull an unsupported Artifact of type %s with %s", type_, identifiers)
            return None

        # assure a state exists
        if not state:
            state = self.get_state(user=user)

        artifact = get_artifact_func(state, *identifiers)

        if not artifact:
            return artifact

        return artifact

    def is_not_syncing_data(self):
        return self.sync_semaphore._value == self.DEFAULT_SEMAPHORE_SIZE

    def _handle_context_update(self, *args, **kwargs):
        ctx: Context = args[0] if len(args) > 0 else None
        if ctx is None or ctx.last_change is None:
            return

        self.recorded_movements.append(ctx)
        if len(self.recorded_movements) > 20:
            self.recorded_movements.pop(0)

        if self.startup_time is None:
            self.startup_time = time.time()

    def _had_recent_human_movement(self):
        """
        An attempt to detect if a change was made from a human, or from a script/automatic process.
        Only relevant in IDA currently.
        """
        if self.deci.name != IDA_DECOMPILER:
            return True

        if len(self.recorded_movements) < 1:
            return False

        time_since_start = time.time() - self.startup_time
        startup_leiniency = 10
        human_delta_time = 1 if time_since_start > startup_leiniency else 2
        last_ctx: Context = self.recorded_movements[-1]
        if last_ctx is None or last_ctx.last_change is None:
            return False

        now = time.time()
        # convert from datetime to timestamp
        last_change = last_ctx.last_change.timestamp() if isinstance(last_ctx.last_change, datetime.datetime) else last_ctx.last_change
        time_since_last_change = now - last_change

        # Check if we have at least 2 movements to compare
        if len(self.recorded_movements) >= 2:
            prev_ctx: Context = self.recorded_movements[-2]

            screen_change = prev_ctx.screen_name != last_ctx.screen_name
            implicit_screen_change = prev_ctx.action == Context.ACT_VIEW_OPEN and last_ctx.action == Context.ACT_VIEW_OPEN
            function_change = prev_ctx.func_addr != last_ctx.func_addr

            # Case 1: A user opens a function or view after being on another view really fast
            # Case 2: A user switches rapidly between the same view
            # Case 3: A user switches functions
            if screen_change or implicit_screen_change or function_change:
                if time_since_last_change < human_delta_time:
                    return False

        return True

    def _commit_hook_based_changes(self, *args, **kwargs):
        """
        A special wrapper for callbacks to only commit artifacts when they are changed by the user, and not
        when they are being pulled in from another users (avoids infinite loops)

        @param args:
        @param kwargs:
        @return:
        """
        if self.should_watch_artifacts() and self._had_recent_human_movement():
            self.commit_artifact(*args, **kwargs)

    @init_checker
    def commit_artifact(self, artifact: Artifact, commit_msg=None, set_last_change=True, make_func=True, from_user=None,
                        deleted=False, **kwargs) -> bool:
        """
        This function is NOT thread safe. You must call it in the order you want commits to appear.
        Additionally, the Artifact must be LIFTED before committing it!
        """
        _l.debug(f"Attempting to push %s...", artifact)
        if not artifact:
            _l.warning("Attempting to push a None artifact, skipping...")
            return False

        try:
            set_art_func = self.ARTIFACT_SET_MAP[artifact.__class__]
            get_art_func = self.ARTIFACT_GET_MAP[artifact.__class__]
        except KeyError:
            _l.info("Attempting to push an unsupported Artifact of type %s", artifact)
            return False

        state: State = self.client.master_state
        # assure functions existence for artifacts requiring a function
        if isinstance(artifact, (FunctionHeader, StackVariable, Comment)) and make_func:
            func_addr = artifact.func_addr if hasattr(artifact, "func_addr") else artifact.addr
            if func_addr is not None and not state.get_function(func_addr):
                state.set_function(
                    Function(addr=func_addr, size=self.deci.get_func_size(func_addr)),
                    set_last_change=set_last_change
                )

        # take the current changes and layer them on top of the change in the state now
        if not set_last_change:
            artifact.reset_last_change()

        identifiers = DecompilerInterface.get_identifiers(artifact)
        current_art = get_art_func(state, *identifiers)
        merged_artifact = self.merge_artifacts(current_art, artifact, merge_level=MergeLevel.OVERWRITE)
        if not merged_artifact:
            return False

        # set the artifact in the target state, likely master
        _l.debug("Setting an artifact now into %s as %s", state, artifact)
        was_set = set_art_func(state, merged_artifact, set_last_change=set_last_change, from_user=from_user, **kwargs)

        # if a struct is deleted remove it from the state dictionary
        if isinstance(artifact, Struct) and deleted:
            del state.structs[artifact.name]

        # TODO: make was_set reliable
        _l.debug("%s committing now with %s", state, commit_msg)
        self.client.master_state = state
        return was_set

    #
    # Fillers:
    # A filler function is generally responsible for pulling down data from a specific user state
    # and reflecting those changes in decompiler view (like the text on the screen). Normally, these changes
    # will also be accompanied by a Git commit to the master users state to save the changes from pull and
    # fill into their BS database. In special cases, a filler may only update the decompiler UI but not directly
    # cause a save of the BS state.
    #

    def fill_artifact(
            self,
            *identifiers,
            artifact_type=None,
            artifact=None,
            user=None,
            state=None,
            master_state=None,
            merge_level=None,
            blocking=True,
            commit_msg=None,
            members=True,
            header=True,
            do_type_search=True,
            do_merge=True,
            fast_only=False,
            **kwargs
    ):
        state: State = state if state is not None else self.get_state(user=user, priority=SchedSpeed.FAST)
        user = user or state.user
        master_state = self.client.master_state
        artifact_type = artifact_type if artifact_type is not None else artifact.__class__
        # TODO: make this work for multiple identifiers (stack vars)
        identifier = identifiers[0]

        # find the state getter and artifact dict for the artifact
        art_dict = self.artifact_dict_map[artifact_type]
        art_state_getter = self.ARTIFACT_GET_MAP[artifact_type]

        # construct and merge the incoming changes from user (or target state) into the master
        # state (which also maybe defined by an artifact being passed in)
        master_artifact = artifact if artifact else art_state_getter(master_state, *identifiers)
        target_artifact = art_state_getter(state, *identifiers)
        if target_artifact is not None:
            # specify to BinSync that this is not user-changed, but merged from someone else
            target_artifact.reset_last_change()

        if do_merge:
            merged_artifact = self.merge_artifacts(
                master_artifact, target_artifact,
                merge_level=merge_level, master_state=master_state
            )
        else:
            merged_artifact = target_artifact

        if merged_artifact is None:
            self.deci.warning(
                f"Failed to merge {master_artifact} with {target_artifact} "
                f"using strategy {self.merge_level if merge_level is None else merge_level}."
            )
            return False

        if isinstance(merged_artifact, Struct):
            if merged_artifact.name.startswith("__"):
                _l.info("Skipping fill for %s because it is a system struct", target_artifact)
                return False

            if not members:
                # for header-only syncs
                merged_artifact.members = {}

            if not header:
                do_type_search = False

        # alert others that we are about to change things in the decompiler
        with self.sync_semaphore:
            try:
                # import all user defined types
                if do_type_search:
                    self.discover_and_sync_user_types(merged_artifact, state=state, master_state=master_state)

                if isinstance(merged_artifact, Function):
                    if isinstance(target_artifact, Function):
                        has_svars = bool(target_artifact.stack_vars)
                        has_fargs = bool(target_artifact.args)
                        needs_decompilation = has_fargs | has_svars
                        fast_only |= not needs_decompilation

                    # in fast only, we disable writes that happen in the decompiler
                    if fast_only:
                        merged_artifact.stack_vars = {}
                        if merged_artifact.header is not None:
                            merged_artifact.header.args = {}
                            merged_artifact.header.type = None

                # set the imports into the decompiler
                art_dict[identifier] = merged_artifact

                # TODO: figure out a way to do this inside LibBS (getting all comments for a func)
                if artifact_type is Function:
                    for addr, cmt in state.get_func_comments(merged_artifact.addr).items():
                        self.fill_artifact(addr, artifact_type=Comment, artifact=cmt, state=state, user=user)

                fill_changes = True
            except Exception as e:
                fill_changes = False
                _l.error("Failed to fill artifact %s because of an error %s", merged_artifact, e)

        self.deci.info(
            f"Successfully synced new changes from {state.user} for {merged_artifact}" if fill_changes
            else f"No new changes or failed to sync from {state.user} for {merged_artifact}"
        )

        if blocking:
            self.commit_artifact(merged_artifact, set_last_change=False, commit_msg=commit_msg, from_user=user)
        else:
            self.schedule_job(
                self.commit_artifact,
                merged_artifact,
                set_last_change=False,
                commit_msg=commit_msg,
                from_user=user,
            )

        return fill_changes

    def fill_functions(self, user=None, do_type_search=True, **kwargs):
        change = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for addr, func in state.functions.items():
            change |= self.fill_artifact(
                addr, artifact_type=Function, state=state, master_state=master_state, do_type_search=do_type_search
            )

        return change

    def fill_structs(self, user=None, **kwargs):
        """
        Grab all the structs from a specified user, then fill them locally

        @param user:
        @param state:
        @return:
        """
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        art_dict = self.artifact_dict_map[Struct]
        for name, struct in state.structs.items():
            # if we already synced a struct that was nested in a parent struct, skip it
            if name in art_dict.keys() and art_dict[name] == struct:
                continue
            changes |= self.fill_artifact(
                name, artifact_type=Struct, user=user
            )

        return changes

    def fill_enums(self, user=None, do_type_search=True, **kwargs):
        """
        Grab all enums and fill it locally

        @param user:
        @param state:
        @return:
        """
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, enum in state.enums.items():
            changes |= self.fill_artifact(
                name, artifact_type=Enum, user=user, state=state, master_state=master_state,
                do_type_search=do_type_search
            )

        return changes

    def fill_global_vars(self, user=None, do_type_search=True, **kwargs):
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for off, gvar in state.global_vars.items():
            changes |= self.fill_artifact(
                off, artifact_type=GlobalVariable, user=user, state=state, master_state=master_state,
                do_type_search=do_type_search
            )

        return changes

    def fill_typedefs(self, user=None, do_type_search=True, **kwargs):
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, typedef in state.typedefs.items():
            changes |= self.fill_artifact(
                name, artifact_type=Typedef, user=user, state=state, master_state=master_state,
                do_type_search=do_type_search
            )

        return changes

    @init_checker
    def fill_segment(self, name, user=None, do_type_search=True, **kwargs):
        """Fill a single segment from another user."""
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        return self.fill_artifact(
            name, artifact_type=Segment, user=user, state=state, master_state=master_state,
            do_type_search=do_type_search
        )

    @init_checker
    def fill_segments(self, user=None, do_type_search=True, **kwargs):
        changes = False
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, segment in state.segments.items():
            changes |= self.fill_artifact(
                name, artifact_type=Segment, user=user, state=state, master_state=master_state,
                do_type_search=do_type_search
            )

        return changes

    def sync_all(self, user=None, **kwargs):
        """
        Connected to the Sync All action:
        syncs in all the data from the targeted user

        @param user:
        @param state:
        @return:
        """
        _l.info("Filling all data from user %s...", user)

        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        fillers = [
            self.fill_enums, self.fill_global_vars, self.fill_functions, self.fill_segments
        ]
        changes = False
        # need to do structs specially
        changes |= self.fill_structs(user=user, state=state, master_state=master_state)

        for filler in fillers:
            changes |= filler(user=user, state=state, master_state=master_state, do_type_search=False)

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
        _l.info("Starting a Magic Sync with a preference for %s", preference_user)
        self.save_native_decompiler_database()

        if self.merge_level == MergeLevel.OVERWRITE:
            _l.warning("Using Magic Sync with OVERWRITE is not supported, switching to NON-CONFLICTING")

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
            Struct: self.fill_artifact,
            #Comment: lambda *x, **y: None,
            Comment: self.fill_artifact,
            Function: self.fill_artifact,
            GlobalVariable: self.fill_artifact,
            Enum: self.fill_artifact
        }
        total_synced = defaultdict(int)

        for artifact_type, filler_func in target_artifacts.items():
            _l.info("Magic Syncing artifacts of type %s now...", artifact_type.__name__)
            pref_state = users_state_map[preference_user]
            for identifier in self.changed_artifacts_of_type(artifact_type, users=all_users + [preference_user],
                                                             states=users_state_map):
                total_synced[artifact_type] += 1
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

                _l.debug("Filling artifact %s now...", pref_art)
                try:
                    filler_func(
                        identifier, artifact_type=artifact_type, artifact=pref_art, state=master_state,
                        commit_msg=f"Magic Synced {pref_art}",
                        merge_level=MergeLevel.NON_CONFLICTING,
                        do_type_search=False
                    )
                except Exception as e:
                    _l.info("Banishing exception: %s", e)

        _l.info("Magic Syncing Completed!")
        # summarize total synchage!
        _l.info(
            "In total: %d Structs, %d Functions, %d Global Variables, and %d Enums were synced.",
            total_synced[Struct], total_synced[Function], total_synced[GlobalVariable], total_synced[Enum]
        )

    def safe_sync_all(self, all_states: list[State]):
        """
        This function attempts to do the following:
        - grab all the states for all users
        - iterate all functions changed for all users, grab two things:
            1. function name
            2. function comments
        - with all function names candidates, remove candidates for ones the master user already has a func name
        """
        addr_to_new_names_and_user = defaultdict(list)
        master_state = next(state for state in all_states if state.user == self.client.master_user)
        changes_per_func = self.compute_changes_per_function(states=all_states)
        for state in all_states:
            if state is master_state:
                continue

            for addr, light_func in state.functions.items():
                name = light_func.name
                if not name:
                    continue

                if self.is_default_name(name):
                    continue

                changes = changes_per_func.get(addr, {}).get(state.user, 0)
                addr_to_new_names_and_user[addr].append((name, state.user, changes))

        # now we have a list of functions that have new names, we want to rank the best one for each func addr
        best_names_and_ids = {}
        for addr, new_names in addr_to_new_names_and_user.items():
            scored_candidates = [(name, user, BSController.readability_score(name), changes) for name, user, changes in new_names]
            # max it by highest changes and then highest readability
            best_candidate = max(scored_candidates, key=lambda x: (x[3], x[2]))
            # name, user, changes num
            best_names_and_ids[addr] = (best_candidate[0], best_candidate[1], best_candidate[2])

        # now we have single name for each function, we for any we don't currently have
        total_change = 0
        for addr, (name, user, changes) in best_names_and_ids.items():
            if user == self.client.master_user:
                continue

            fast_func = self.deci.fast_get_function(addr)
            # the function must exist in the decompiler, and have a default name
            if fast_func is None:
                continue

            update_cmt = ""
            if addr in self.safe_synced_users:
                old_name, old_user, old_change = self.safe_synced_users[addr]
                if old_user == user and changes > old_change:
                    update_cmt = f"[binsync]: {old_user} has {changes - old_change} new changes.\n"

            needs_new_name = self.is_default_name(fast_func.name) and fast_func.name != name
            if not needs_new_name and not update_cmt:
                continue

            # fill the function with the new name
            succeed = False
            if needs_new_name:
                fast_func.name = name
                succeed = self.fill_artifact(
                    fast_func.addr, artifact_type=Function, artifact=fast_func, user=user, do_merge=False, fast_only=True
                )
            if update_cmt:
                try:
                    old_cmt: Comment = self.deci.comments[fast_func.addr]
                except KeyError:
                    old_cmt = Comment(addr=fast_func.addr, comment="")

                if old_cmt and old_cmt.comment and "[binsync]" in old_cmt.comment:
                    # remove the first line with the old comment
                    old_cmt.comment = "\n".join(old_cmt.comment.split("\n")[1:])
                    old_cmt.comment = update_cmt + old_cmt.comment
                else:
                    old_cmt.comment = update_cmt + old_cmt.comment

                self.fill_artifact(
                    fast_func.addr, artifact_type=Comment, artifact=old_cmt, user=user, do_merge=False, fast_only=True
                )

            self.safe_synced_users[addr] = (name, user, changes)
            if succeed:
                total_change += 1

        if total_change:
            _l.info("Safe Syncing completed with %d changes.", total_change)

    @staticmethod
    def tokenize_varname(name):
        """
        Tokenizes a variable name by splitting on underscores and identifying camelCase boundaries.
        Returns a list of lowercase tokens.
        """
        # Split on underscores
        tokens = name.split('_')
        camel_tokens = []
        # Further split tokens with camelCase using a regex pattern.
        for token in tokens:
            parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])', token)
            if parts:
                camel_tokens.extend(parts)
            else:
                camel_tokens.append(token)
        return [tok.lower() for tok in camel_tokens if tok]

    @staticmethod
    def readability_score(var_name):
        """
        Calculates a readability score for the variable name based on word frequency.
        Uses the logarithm of the word frequency probabilities (words not found get a small fallback value).
        A higher score means the name looks more natural.
        """
        tokens = BSController.tokenize_varname(var_name)
        score = 0.0
        # For each token, look up the word frequency in English.
        for token in tokens:
            freq = word_frequency(token, 'en')
            # Avoid log(0); if the token frequency is 0, assign a small fallback frequency.
            if freq == 0:
                freq = 1e-9
            score += math.log(freq)
        return score

    @staticmethod
    def is_default_name(name: str):
        BAD_STARTS = ("sub_", "FUNC_")
        for starter in BAD_STARTS:
            if name.startswith(starter):
                return True

        return False

    #
    # Force Push
    #

    @init_checker
    def force_push_functions(self, func_addrs: List[int], use_decompilation=False):
        """
        Collects the functions currently stored in the decompiler, not the BS State, and commits it to
        the master users BS Database. Function addrs should be in the lifted form.

        TODO: push the comments and custom types that are associated with each stack vars
        TODO: refactor to use internal push_function for correct commit message
        """

        # NOTE: The following check allows to show a warning to a user and to
        # avoid a ZeroDivisionError in the progress_bar declared later below
        if not func_addrs:
            _l.warning("Ignored force push, no function selected")
            return

        master_state: State = self.client.master_state
        committed = 0
        progress_str = "Decompiling functions to push..." if use_decompilation else "Collecting functions..."

        funcs = []
        if use_decompilation:
            for func_addr in progress_bar(func_addrs, gui=not self.headless, desc=progress_str):
                f = self.deci.functions[func_addr]
                if not f:
                    _l.warning(f"Failed to force push function @ %s", func_addr)
                    continue

                funcs.append(f)
        else:
            # no progress bar needed!
            _func_addrs = set(func_addrs)
            for addr, func in self.deci.functions.items():
                if addr in _func_addrs:
                    funcs.append(func)

        for func in funcs:
            master_state.set_function(func)
        committed += len(funcs)

        # commit the master state back!
        master_state.last_commit_msg = f"Force pushed {committed} functions"
        self.client.master_state = master_state
        self.deci.info(f"Function force push successful: committed {committed} functions.")

    @init_checker
    def force_push_global_artifacts(self, lookup_items: List):
        """
        Collects the global artifact (struct, gvar, enum) currently stored in the decompiler, not the BS State,
        and commits it to the master users BS Database.

        @param lookup_item:
        @return: Success of committing the Artifact
        """
        master_state: State = self.client.master_state
        committed = 0
        for lookup_key in lookup_items:
            if isinstance(lookup_key, int):
                art = self.deci.global_vars[lookup_key]
                master_state.global_vars[art.addr] = art
            else:
                art = None
                # structs always first
                try:
                    art = self.deci.structs[lookup_key]
                    master_state.structs[lookup_key] = art
                except KeyError:
                    pass

                if art is None:
                    master_state.enums[lookup_key] = self.deci.enums[lookup_key]
            committed += 1

        master_state.last_commit_msg = f"Force pushed {committed} global artifacts"
        self.client.master_state = master_state
        self.deci.info(f"Globals force push successful: committed {committed} artifacts.")

    @init_checker
    def force_push_segments(self, segment_names: List[int]):
        """
        Collects the segments currently stored in the decompiler, not the BS State,
        and commits them to the master users BS Database.

        @param segment_names: List of segment names to push
        @return: Success of committing the Segments
        """
        if not segment_names:
            _l.warning("Ignored segments force push, no segments selected")
            return

        master_state: State = self.client.master_state
        committed = 0
        
        for segment_name in segment_names:
            try:
                segment = self.deci.segments[segment_name]
                if segment:
                    master_state.set_segment(segment)
                    committed += 1
                else:
                    _l.warning("Failed to force push segment @ %s", segment_name)
            except KeyError:
                _l.warning("Segment at %s not found in decompiler", segment_name)

        master_state.last_commit_msg = f"Force pushed {committed} segments"
        self.client.master_state = master_state
        self.deci.info(f"Segments force push successful: committed {committed} segments.")

    #
    # Utils
    #

    def merge_artifacts(self, art1: Artifact, art2: Artifact, merge_level=None, **kwargs) -> Optional[Artifact]:
        if merge_level is None:
            merge_level = self.merge_level

        # error case
        if art1 is None and art2 is None:
            _l.warning("Attempting to merge two None artifacts, skipping...")
            return None

        # merge case does not matter if there is only the new artifact
        if art2 is None:
            return art1.copy()
        # always overwrite if the first artifact is None
        if art1 is None or (art1 == art2):
            return art2.copy() if art2 else None

        if merge_level == MergeLevel.OVERWRITE or (not art1) or (art1 == art2):
            merge_art = art1.overwrite_merge(art2)
        elif merge_level == MergeLevel.NON_CONFLICTING:
            merge_art = art1.nonconflict_merge(art2, **kwargs)
        elif merge_level == MergeLevel.MERGE:
            # Manual merge is only supported for function name conflicts in GUI mode
            if isinstance(art1, Function) and isinstance(art2, Function):
                merge_art = self._merge_function_with_dialog(art1, art2, **kwargs)
            else:
                _l.debug("Manual merge not supported for %s, using non-conflict merge", type(art1).__name__)
                merge_art = art1.nonconflict_merge(art2, **kwargs)

        else:
            raise Exception("Your BinSync Client has an unsupported Sync Level activated")

        return merge_art

    def _merge_function_with_dialog(self, func1: Function, func2: Function, **kwargs) -> Function:
        """
        Merge two functions, opening a dialog for name conflicts if in GUI mode.
        For all other attributes, use non-conflicting merge.
        """
        # Start with a non-conflicting merge for everything
        merged_func = func1.nonconflict_merge(func2, **kwargs)

        # Check if there's a name conflict that needs manual resolution
        name1 = func1.name
        name2 = func2.name

        # Only open dialog if both names exist, are different, and neither is a default name
        has_conflict = (
            name1 is not None and name2 is not None and
            name1 != name2 and
            not self.is_default_name(name1) and
            not self.is_default_name(name2)
        )

        if has_conflict and not self.headless:
            from binsync.ui.function_merge_dialog import resolve_function_name_conflict

            _l.info("Function name conflict detected: '%s' vs '%s'", name1, name2)
            choice = resolve_function_name_conflict(name1, name2)

            if choice == "current":
                merged_func.name = name1
                _l.info("User selected current name: '%s'", name1)
            elif choice == "incoming":
                merged_func.name = name2
                _l.info("User selected incoming name: '%s'", name2)
            else:
                # Dialog was cancelled, keep the non-conflicting merge result
                _l.info("Merge dialog cancelled, keeping non-conflicting merge result")
        elif has_conflict:
            _l.debug("Function name conflict in headless mode, using non-conflicting merge")

        return merged_func

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
            _l.warning("Attempted to get changed artifacts of type %s which is unsupported", type_)
            return set()

        known_arts = set()
        for username in users:
            state = states[username]
            artifact_dict: Dict = getattr(state, prop_name)
            for identifier in artifact_dict:
                known_arts.add(identifier)

        return known_arts

    def discover_and_sync_user_types(self, artifact: Artifact, master_state=None, state=None):
        imported_types = False
        if not artifact:
            return imported_types

        if isinstance(artifact, Function):
            # header
            if artifact.header:
                imported_types |= self.discover_and_sync_user_types(artifact.header, master_state=master_state,
                                                                    state=state)

            # stack vars
            if artifact.stack_vars:
                for sv in artifact.stack_vars.values():
                    imported_types |= self.discover_and_sync_user_types(sv, master_state=master_state, state=state)
        elif isinstance(artifact, FunctionHeader):
            # ret type
            if artifact.type:
                imported_types |= self.sync_user_type(artifact.type, master_state=master_state, state=state)

            # args
            if artifact.args:
                for arg in artifact.args.values():
                    imported_types |= self.discover_and_sync_user_types(arg, master_state=master_state, state=state)
        elif isinstance(artifact, FunctionArgument):
            imported_types |= self.sync_user_type(artifact.type, master_state=master_state, state=state)
        elif isinstance(artifact, StackVariable):
            imported_types |= self.sync_user_type(artifact.type, master_state=master_state, state=state)
        elif isinstance(artifact, GlobalVariable):
            imported_types |= self.sync_user_type(artifact.type, master_state=master_state, state=state)
        elif isinstance(artifact, Struct):
            for memb in artifact.members.values():
                imported_types |= self.discover_and_sync_user_types(memb, master_state=master_state, state=state)
        elif isinstance(artifact, StructMember):
            imported_types |= self.sync_user_type(artifact.type, master_state=master_state, state=state)
        else:
            _l.debug(f"Unsupported artifact type %s for user defined type discovery", artifact)

        return imported_types

    def type_is_user_defined(self, type_str, state=None) -> Tuple[Optional[str], Optional[Union[Struct, Enum, Typedef]]]:
        if not type_str:
            return None, None

        type_: CType = self.deci.type_parser.parse_type(type_str)
        if not type_:
            # it was not parseable
            return None, None

        # type is known and parseable
        if not type_.is_unknown:
            return None, None

        base_type_str = type_.base_type.type
        # this could go wrong in overlapps of type names
        for type_name, type_list in ((Struct, state.structs.keys()), (Enum, state.enums.keys()), (Typedef, state.typedefs.keys())):
            if base_type_str in type_list:
                return base_type_str, type_name
        return None, None

    def sync_user_type(self, type_str, **kwargs):
        state = kwargs.pop('state')
        master_state = kwargs['master_state']
        base_type_str, base_type_cls = self.type_is_user_defined(type_str, state=state)
        if base_type_str is None:
            return False

        changes = False
        if base_type_cls is Struct:
            struct: Struct = state.get_struct(base_type_str)
            if not struct:
                return False

            nested_undefined_structs = False
            for off, memb in struct.members.items():
                user_type, type_cls = self.type_is_user_defined(memb.type, state=state)
                if type_cls is Struct and user_type not in master_state.structs.keys():
                    # should we ever happen to have a struct with a nested type that is
                    # also a struct that we don't have in our master_state, then we give up
                    # and attempt to fill all structs to resolve type issues
                    nested_undefined_structs = True
                    _l.info("Nested undefined structs detected, pulling all structs from %s", state.user)
                    break

            changes = self.fill_artifact(
                base_type_str, artifact_type=Struct, state=state, **kwargs
            ) if not nested_undefined_structs else self.fill_structs(state=state, **kwargs)
        elif base_type_cls is Enum:
            changes = self.fill_artifact(
                base_type_str, artifact_type=Enum, state=state, **kwargs
            )
        elif base_type_cls is Typedef:
            changes = self.fill_artifact(
                base_type_str, artifact_type=Typedef, state=state, **kwargs
            )

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

    def load_saved_config(self) -> Optional[BinSyncBSConfig]:
        config = BinSyncBSConfig().load_from_file()
        if not config:
            return None

        self.config = config
        _l.info("Loaded configuration file: '%s'", self.config.save_location)
        self.table_coloring_window = config.table_coloring_window or self.table_coloring_window
        self.merge_level = config.merge_level or self.merge_level
        if config.precise_diff_preview is not None:
            self.precise_diff_preview = config.precise_diff_preview

        if config.log_level == "debug":
            logging.getLogger("binsync").setLevel("DEBUG")
        else:
            logging.getLogger("binsync").setLevel("INFO")

        return self.config

    #
    # View Utils
    #

    def compute_changes_per_function(self, exclude_master=False, client=None, commit_hash=None, states=None):
        """
        Computes the number of changes per artifact type.
        TODO: support more than just functions
        TODO: make this not such a poormans counter. We should be using commits not this hack
        """
        if client is None:
            client = self.client
        before_ts = None
        if commit_hash is not None:
            try:
                commit_ref = client.repo.commit(commit_hash)
            except Exception as e:
                _l.error("Failed to get commit %s because of %s", commit_hash, e)
                commit_ref = None

            if commit_ref is not None:
                before_ts = commit_ref.committed_date

        # gather all the states
        if states:
            all_states = states
        else:
            all_states = client.all_states(before_ts=before_ts)

        if exclude_master:
            all_states = [s for s in all_states if s.user != client.master_user]

        func_addrs = list(self.deci.functions.keys())
        function_counts = {addr: defaultdict(int) for addr in func_addrs}
        for state in all_states:
            for func_addr, func in state.functions.items():
                func: Function
                changes = 0
                # check the parameters
                header: FunctionHeader = func.header
                if header:
                    if header.name:
                        changes += 1
                    for arg in header.args.values():
                        arg: FunctionArgument
                        if arg.name:
                            changes += 1
                        if arg.type:
                            changes += 1
                    if header.type:
                        changes += 1
                # check the stack vars
                for sv in func.stack_vars.values():
                    sv: StackVariable
                    if sv.name:
                        changes += 1
                    if sv.type:
                        changes += 1

                if func_addr not in function_counts:
                    self.deci.warning(f"Function {func_addr} not found in the decompiler")
                    function_counts[func_addr] = defaultdict(int)

                function_counts[func_addr][state.user] = changes

        return function_counts

    def show_progress_window(self, *args, tag=None, **kwargs):
        """
        TODO: re-enable this later when you figure out how fix the apparent thread/proccess issue in IDA Pro
        """

        from binsync.ui.progress_graph.progress_window import ProgressGraphWidget

        # TODO: XXX: re-enable this later
        #if self.progress_view_open:
        #    self.deci.info("Progress view already open")
        #    return

        self.deci.info("Collecting data to make progress view now...")
        graph = self.deci.get_callgraph()
        if tag == "master":
            tag = None

        self.deci.gui_attach_qt_window(ProgressGraphWidget, "Progress View", graph=graph, controller=self, tag=tag)
        self.progress_view_open = True


    def preview_function_changes(self, func_addr=None, user=None, **kwargs):
        """
        Get a preview of the function differences between two functions about to be synced.

        This was written for the pop-up window that appears when hover over a sync or sync from in the 
        function and context panel. Note that this only applies to functions and their comments. (Not for 
        artifacts like structs etc). 

        The approach to this is getting the two artifacts in question and creating a dictionary with information 
        on name, type, args, and comments for master and target functions which can then be parsed to see 
        how they differ. 
        """
        state = self.get_state(user=user, priority=SchedSpeed.FAST)
        user = user or state.user
        
        # Get the master function based on the selected method
        if self.precise_diff_preview:
            master_func = self.deci.functions.get(func_addr)
        else:
            master_state = self.client.master_state
            master_func = master_state.get_function(func_addr)
        
        target_func = state.get_function(func_addr)
        
        # A lot of repetition so this is just a helper to get the relevant attributes 
        def get_header_attr(func, attr):
            return getattr(func.header, attr, None) if func and func.header else None
        
        # Get the comments where each comment is a dictionary 
        get_comments = lambda state_obj: {addr: cmt.comment for addr, cmt in state_obj.get_func_comments(func_addr).items()}
        
        # Get master comments based on the selected method
        if self.precise_diff_preview:
            master_comments = {}
            if master_func:
                func_size = master_func.size if hasattr(master_func, 'size') else 0x1000
                for addr, cmt in self.deci.comments.items():
                    if master_func.addr <= addr < (master_func.addr + func_size):
                        master_comments[addr] = cmt.comment
        else:
            master_comments = get_comments(self.client.master_state)
        
        target_comments = get_comments(state)
        
        diffs = {
            'name': {
                # can change this to use helper func since func and func.header should have same name 
                'master': master_func.name if master_func else None,
                'target': target_func.name if target_func else None
            },
            'args': {
                'master': get_header_attr(master_func, 'args') or {},
                'target': get_header_attr(target_func, 'args') or {}
            },
            'type': {
                'master': get_header_attr(master_func, 'type'),
                'target': get_header_attr(target_func, 'type')
            },
            'stack_vars': {
                'master': master_func.stack_vars if master_func else {},
                'target': target_func.stack_vars if target_func else {}
            },
            'comments': {
                'master': master_comments,
                'target': target_comments
            }
        }

        return diffs
            

