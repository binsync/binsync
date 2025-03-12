import logging
import threading
import datetime
import time
from collections import defaultdict
from functools import wraps
from typing import Dict, Iterable, Optional, Union, List, Tuple

from libbs.api.utils import progress_bar
from libbs.artifacts import (
    Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct, FunctionArgument, StructMember, Typedef
)
from libbs.api import DecompilerInterface
from libbs.api.type_parser import CType

from binsync.core.client import Client, SchedSpeed, Scheduler, Job
from binsync.core.state import State
from binsync.core.user import User
from binsync.configuration import BinSyncBSConfig

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
        FunctionHeader, StackVariable, Comment, GlobalVariable, Enum, Struct, Typedef
    )

    ARTIFACT_SET_MAP = {
        Function: State.set_function,
        FunctionHeader: State.set_function_header,
        StackVariable: State.set_stack_variable,
        Comment: State.set_comment,
        GlobalVariable: State.set_global_var,
        Struct: State.set_struct,
        Enum: State.set_enum,
        Typedef: State.set_typedef
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
        (Typedef, GET_MANY): State.get_typedefs
    }

    DEFAULT_SEMAPHORE_SIZE = 100

    def __init__(self, decompiler_interface: DecompilerInterface = None, headless=False, auto_commit=True,
                 reload_time=10, **kwargs):
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

        # artifact map
        self.artifact_dict_map = {
            Function: self.deci.functions,
            Comment: self.deci.comments,
            GlobalVariable: self.deci.global_vars,
            Enum: self.deci.enums,
            Typedef: self.deci.typedefs,
            Struct: self.deci.structs,
            Patch: self.deci.patches
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
        self.user_states_update_thread = threading.Thread(target=self.updater_routine)

        # other properties
        self.progress_view_open = False

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
        self.user_states_update_thread.daemon = True
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
            _l.info(f"Attempting to pull an unsupported Artifact of type {type_} with {identifiers}")
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

    def _commit_hook_based_changes(self, *args, **kwargs):
        """
        A special wrapper for callbacks to only commit artifacts when they are changed by the user, and not
        when they are being pulled in from another users (avoids infinite loops)

        @param args:
        @param kwargs:
        @return:
        """
        if self.should_watch_artifacts():
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
            _l.warning(f"Attempting to push a None artifact, skipping...")
            return False

        try:
            set_art_func = self.ARTIFACT_SET_MAP[artifact.__class__]
            get_art_func = self.ARTIFACT_GET_MAP[artifact.__class__]
        except KeyError:
            _l.info(f"Attempting to push an unsupported Artifact of type {artifact}")
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
        _l.debug(f"Setting an artifact now into {state} as {artifact}")
        was_set = set_art_func(state, merged_artifact, set_last_change=set_last_change, from_user=from_user, **kwargs)

        # if a struct is deleted remove it from the state dictionary
        if isinstance(artifact, Struct) and deleted:
            del state.structs[artifact.name]

        # TODO: make was_set reliable
        _l.debug(f"{state} committing now with {commit_msg}")
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

        merged_artifact = self.merge_artifacts(
            master_artifact, target_artifact,
            merge_level=merge_level, master_state=master_state
        )

        if merged_artifact is None:
            self.deci.warning(
                f"Failed to merge {master_artifact} with {target_artifact} "
                f"using strategy {self.merge_level if merge_level is None else merge_level}."
            )
            return False

        if isinstance(merged_artifact, Struct):
            if merged_artifact.name.startswith("__"):
                _l.info(f"Skipping fill for {target_artifact} because it is a system struct")
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

                # set the imports into the decompiler
                art_dict[identifier] = merged_artifact

                # TODO: figure out a way to do this inside LibBS (getting all comments for a func)
                if artifact_type is Function:
                    for addr, cmt in state.get_func_comments(merged_artifact.addr).items():
                        self.fill_artifact(addr, artifact_type=Comment, artifact=cmt, state=state, user=user)

                fill_changes = True
            except Exception as e:
                fill_changes = False
                _l.error(f"Failed to fill artifact {merged_artifact} because of an error {e}")

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
        # only do struct headers for circular references
        master_state, state = self.get_master_and_user_state(user=user, **kwargs)
        for name, struct in state.structs.items():
            changes |= self.fill_artifact(
                name, artifact_type=Struct, user=user, state=state, master_state=master_state, members=False
            )

        for name, struct in state.structs.items():
            changes |= self.fill_artifact(
                name, artifact_type=Struct, user=user, state=state, master_state=master_state, header=False
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

    def sync_all(self, user=None, **kwargs):
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
            self.fill_enums, self.fill_global_vars, self.fill_functions
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
        _l.info(f"Staring a Magic Sync with a preference for {preference_user}")
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
            #Struct: self.fill_artifact,
            #Comment: lambda *x, **y: None,
            Comment: self.fill_artifact,
            Function: self.fill_artifact,
            #GlobalVariable: self.fill_artifact,
            #Enum: self.fill_artifact
        }
        total_synced = defaultdict(int)

        for artifact_type, filler_func in target_artifacts.items():
            _l.info(f"Magic Syncing artifacts of type {artifact_type.__name__} now...")
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

                _l.debug(f"Filling artifact {pref_art} now...")
                try:
                    filler_func(
                        identifier, artifact_type=artifact_type, artifact=pref_art, state=master_state,
                        commit_msg=f"Magic Synced {pref_art}",
                        merge_level=MergeLevel.NON_CONFLICTING,
                        do_type_search=False
                    )
                except Exception as e:
                    _l.info(f"Banishing exception: {e}")

        _l.info("Magic Syncing Completed!")
        # summarize total synchage!
        _l.info(f"In total: {total_synced[Struct]} Structs, {total_synced[Function]} Functions, "
                f"{total_synced[GlobalVariable]} Global Variables, and {total_synced[Enum]} Enums were synced.")

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

        self.client.master_state = master_state
        self.deci.info(f"Globals force push successful: committed {committed} artifacts.")

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
                    _l.info(f"Nested undefined structs detected, pulling all structs from {state.user}")
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
        _l.info(f"Loaded configuration file: '{self.config.save_location}'")
        self.table_coloring_window = config.table_coloring_window or self.table_coloring_window
        self.merge_level = config.merge_level or self.merge_level

        if config.log_level == "debug":
            logging.getLogger("binsync").setLevel("DEBUG")
        else:
            logging.getLogger("binsync").setLevel("INFO")

        return self.config

    #
    # View Utils
    #

    def compute_changes_per_function(self, exclude_master=False, client=None, commit_hash=None):
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
                _l.error(f"Failed to get commit {commit_hash} because of {e}")
                commit_ref = None

            if commit_ref is not None:
                before_ts = commit_ref.committed_date

        # gather all the states
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
