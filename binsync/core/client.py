import logging
import pathlib
import os
import re
import shutil
import subprocess
import datetime
from functools import wraps
from typing import Iterable, Optional
from pathlib import Path
import tempfile

import filelock
import pygit2
import toml

from binsync.core.user import User
from binsync.configuration import BinSyncBSConfig, ProjectData
from binsync.core.errors import ExternalUserCommitError, MetadataNotFoundError
from binsync.core.state import State, toml_file_to_dict
from binsync.core.scheduler import Scheduler, Job, SchedSpeed
from binsync.core.cache import Cache


l = logging.getLogger(__name__)
BINSYNC_BRANCH_PREFIX = 'binsync'
BINSYNC_ROOT_BRANCH = f'{BINSYNC_BRANCH_PREFIX}/__root__'

logging.getLogger("git").setLevel(logging.ERROR)


class ConnectionWarnings:
    HASH_MISMATCH = 0


def atomic_git_action(f):
    """
    Assures that any function called with this decorator will execute in-order, atomically, on a single thread.
    This all assumes that the function you are passing is a member of the Client class, which will also have
    a scheduler. This also means that this can only be called after the scheduler is started. This also requires a
    Cache. Generally, just never call functions with this decorator until the Client is done initing.

    This function will also attempt to check the cache for requested data on the same thread the original call
    was made from. If not found, the atomic scheduling is done.

    @param f:   A Client object function
    @return:
    """
    @wraps(f)
    def _atomic_git_action(self: "Client", *args, **kwargs):
        no_cache = kwargs.get("no_cache", False)
        if not no_cache:
            # cache check
            cache_item = self.check_cache_(f, **kwargs)
            if cache_item is not None:
                return cache_item

        # non cache available, queue it up!
        priority = kwargs.get("priority", None) or SchedSpeed.SLOW
        ret_val = self.scheduler.schedule_and_wait_job(
            Job(f, self, *args, **kwargs),
            priority=priority
        )

        if ret_val:
            self._set_cache(f, ret_val, **kwargs)

        return ret_val if ret_val is not None else {}

    return _atomic_git_action


class Client:
    DEFAULT_COMMIT_MSG = "Generic BS Commit"

    def __init__(
        self,
        master_user: str,
        repo_root: str,
        binary_hash: bytes,
        remote: str = "origin",
        commit_interval: int = 10,
        commit_batch_size: int = 10,
        init_repo: bool = False,
        remote_url: Optional[str] = None,
        ssh_agent_pid: Optional[int] = None,
        ssh_auth_sock: Optional[str] = None,
        push_on_update=True,
        pull_on_update=True,
        commit_on_update=True,
        temp_directory=None,
        ignore_lock=False,
        init_user_branch=True,
        **kwargs,
    ):
        """
        The Client class is responsible for making the low-level Git operations for the BinSync environment.
        Things like committing, pulling, and pushing all happen on the client level. It also starts a thread
        for continuous pushing.

        :param master_user:         Username of the user that is initing the client (the master user)
        :param repo_root:           Path to the BinSync repo where the project will be stored
        :param binary_hash:         The hash, usually md5, of the binary the client is connected for
        :param remote:              The optional Git remote (usually origin)
        :param commit_interval:     The seconds between each commit in the worker thread
        :param init_repo:           Bool to decide initing for both remote and local repos
        :param remote_url:          Remote URL to a Git Repo which may be used for cloning or initing
        :param ssh_agent_pid:       SSH Agent PID
        :param ssh_auth_sock:       SSH Auth Socket
        """
        self._ignore_lock = ignore_lock
        self.master_user = master_user
        self.repo_root = repo_root
        self.binary_hash = binary_hash
        self.remote = remote
        self.repo = None
        self.repo_lock = None
        self.pull_on_update = pull_on_update
        self.push_on_update = push_on_update
        self.commit_on_update = commit_on_update
        self._temp_directory: tempfile.TemporaryDirectory | None = temp_directory

        # validate this username can exist
        if not master_user or master_user.endswith('/') or '__root__' in master_user:
            raise Exception(f"Bad username: {master_user}")

        # ssh-agent info
        self.ssh_agent_pid = ssh_agent_pid  # type: int
        self.ssh_auth_sock = ssh_auth_sock  # type: str
        self.connection_warnings = []

        self._repo_lock_path = Path(self.repo_root + "/.git/binsync.lock")

        # job scheduler
        self.cache = Cache(master_user=master_user)
        self.scheduler = Scheduler(name="GitScheduler")

        # create, init, and checkout Git repo
        self.repo = self._get_or_init_binsync_repo(remote_url, init_repo)
        self.scheduler.start_worker_thread()
        if init_user_branch:
            self._get_or_init_user_branch()

        # timestamps
        self._commit_interval = commit_interval
        self._commit_batch_size = commit_batch_size
        self._last_push_time = None  # type: datetime.datetime
        self.last_push_attempt_time = None  # type: datetime.datetime
        self._last_pull_time = None  # type: datetime.datetime
        self.last_pull_attempt_time = None  # type: datetime.datetime
        self._last_commit_time = None # type: datetime.datetime

        self.active_remote = True
        # force a state update on init
        self.master_state = self.get_state(no_cache=True)

    def copy(self, copy_files=False):
        temp_dir = None
        repo_root = self.repo_root
        if copy_files:
            # go to the repo root and copy the entire tree
            temp_dir = tempfile.TemporaryDirectory()
            abs_path_str = str(Path(temp_dir.name).absolute())
            shutil.copytree(self.repo_root, abs_path_str, dirs_exist_ok=True)
            repo_root = abs_path_str

        return Client(
            master_user=self.master_user,
            repo_root=repo_root,
            binary_hash=self.binary_hash,
            remote=self.remote,
            commit_interval=self._commit_interval,
            commit_batch_size=self._commit_batch_size,
            init_repo=False,
            remote_url=None,
            ssh_agent_pid=self.ssh_agent_pid,
            ssh_auth_sock=self.ssh_auth_sock,
            push_on_update=self.push_on_update,
            pull_on_update=self.pull_on_update,
            commit_on_update=self.commit_on_update,
            temp_directory=temp_dir,
            ignore_lock=self._ignore_lock or copy_files,
            init_user_branch=not copy_files,
        )

    def __del__(self):
        if self._temp_directory is not None:
            self._temp_directory.cleanup()

        self.shutdown()

    #
    # Initializers
    #

    def _get_or_init_user_branch(self):
        """
        Creates a user branch if the user is new, otherwise it gets the branch of the same
        name as the user

        @return:
        """
        try:
            branch = self.repo.lookup_branch(self.user_branch_name)
            if not branch:
                raise KeyError
        except KeyError:
            # Create new branch from root
            root_ref = self.repo.lookup_reference(f'refs/heads/{BINSYNC_ROOT_BRANCH}')
            if not root_ref:
                raise Exception(f"Cannot find {BINSYNC_ROOT_BRANCH} branch")
            self.repo.create_branch(self.user_branch_name, self.repo[root_ref.target])

        # Checkout the branch with force to handle any conflicts
        ref = self.repo.lookup_reference(f'refs/heads/{self.user_branch_name}')
        self.repo.checkout(ref, strategy=pygit2.GIT_CHECKOUT_FORCE)

    def _get_or_init_binsync_repo(self, remote_url, init_repo):
        """
        Gets the BinSync repo from either a local or remote git location and then sets up the repo as well
        as checks that the repo is the right repo for the current binary.

        When getting the repo there are four scenarios:
        1. The user fills out the remote_url and does not try to init it. In this case we should clone down
           the repo and assure that the head is remote/binsync/__root__
        2. The user fills out the remote_url and want to init it. In this case, we should clone it down to the repo
           root specified in the path. If there is no path, just place it locally then try to set it up with a hash
        3. The user fills out only the path of the git repo (no remote), then we just need to get that local git
           repo and assure it is a BinSync repo
        4. Last case is what happens if a user wants to init a local folder that is not a Git folder. In this case,
           they will be offline but will have a local git repo.

        @param remote_url:
        @param init_repo:
        @return:
        """
        if remote_url:
            # given a remove URL and no local folder, make it based on the URL name
            if not self.repo_root:
                self.repo_root = re.findall(r"/(.*)\.git", remote_url)[0]

            self.repo = pygit2.clone_repository(remote_url, self.repo_root)

            if init_repo:
                if self.repo.lookup_branch(BINSYNC_ROOT_BRANCH):
                    raise ValueError("Can't init this remote repo since a BinSync root already exists")
                
                self._setup_repo()
        else:
            try:
                self.repo = pygit2.Repository(self.repo_root)

                # update view of remote branches (which may be new)
                self._localize_remote_branches()

                if init_repo:
                    raise Exception("Could not initialize repository - it already exists!")
                if not self.repo.lookup_branch(BINSYNC_ROOT_BRANCH):
                    raise Exception(f"This is not a BinSync repo - it must have a {BINSYNC_ROOT_BRANCH} branch.")
            except (KeyError, pygit2.GitError):
                if init_repo:
                    # case 3
                    self.repo = pygit2.init_repository(self.repo_root)
                    self._setup_repo()
                else:
                    raise Exception("Failed to connect or create a BinSync repo")

        stored = self._get_stored_hash()
        if stored != self.binary_hash:
            self.connection_warnings.append(ConnectionWarnings.HASH_MISMATCH)

        assert not self.repo.is_bare, "it should not be a bare repo"

        self.repo_lock = filelock.FileLock(str(self._repo_lock_path))
        should_delete_lock = False
        try:
            self.repo_lock.acquire(timeout=0)
        except filelock.Timeout as e:
            if not self._ignore_lock:
                raise Exception("Can only have one binsync client touching a local repository at once.\n"
                            "If the previous client crashed, you need to delete " + self.repo_root +
                            "/.git/binsync.lock") from e
            should_delete_lock = True

        if should_delete_lock:
            if self._repo_lock_path.exists():
                self._repo_lock_path.unlink(missing_ok=True)
            self.repo_lock = filelock.FileLock(str(self._repo_lock_path))
            self.repo_lock.acquire(timeout=0)

        return self.repo

    def _setup_repo(self):
        """
        For use in initializing folder that is not yet a Git repo.

        @return:
        """
        # Create initial files
        with open(os.path.join(self.repo_root, ".gitignore"), "w") as f:
            f.write(".git/*\n")
        with open(os.path.join(self.repo_root, "binary_hash"), "w") as f:
            f.write(self.binary_hash)

        # Stage and commit
        index = self.repo.index
        index.add(".gitignore")
        index.add("binary_hash")
        tree = index.write_tree()
        author = pygit2.Signature('BinSync', 'binsync@auto.com')
        commit_id = self.repo.create_commit('HEAD', author, author, "Root commit", tree, [])

        # Create root branch pointing to our new commit
        self.repo.create_branch(BINSYNC_ROOT_BRANCH, self.repo[commit_id])

    #
    # Public Properties
    #

    @property
    def master_state(self) -> State:
        return self.cache.get_state(user=self.master_user)

    @master_state.setter
    def master_state(self, state):
        self.cache.set_state(state, user=self.master_user)

    @property
    def last_push_ts(self):
        return self._last_push_time

    @property
    def last_pull_ts(self):
        return self._last_pull_time

    @property
    def last_commit_ts(self):
        return self._last_commit_time

    @property
    def user_branch_name(self):
        return f"{BINSYNC_BRANCH_PREFIX}/{self.master_user}"

    #
    # Atomic Public API
    #

    @atomic_git_action
    def users(self, priority=None, no_cache=False) -> Iterable[User]:
        if not no_cache:
            cached = self.cache.users()
            if cached:
                return cached

        users = []
        for branch in self.repo.branches:
            if not branch.startswith(BINSYNC_BRANCH_PREFIX) or branch == BINSYNC_ROOT_BRANCH:
                continue
            try:
                ref = self.repo.lookup_reference(f'refs/heads/{branch}')
                tree = self.repo[ref.target].tree
                metadata = self._load_toml_from_tree(tree, "metadata.toml")
                if metadata:
                    user = User.from_metadata(metadata)
                    users.append(user)
            except (KeyError, ValueError):
                continue

        if users:
            self.cache.set_users(users)
        return users

    @staticmethod
    def parse_state_from_commit(repo: pygit2.Repository, user=None, commit_hash=None, is_master=False, client=None) -> State:
        if user is None and commit_hash is None:
            raise ValueError("Must specify either a user or a commit hash")

        state = State(None)
        try:
            state = State.parse(
                Client._get_tree(user, repo, commit_hash=commit_hash),
                client=client
            )
        except MetadataNotFoundError:
            if is_master:
                # create of the first state ever
                state = State(user, client=client)
        except Exception as e:
            if is_master:
                raise
            else:
                l.critical(f"Invalid state for {user}, dropping: {e}")
                state = State(user)

        return state


    @atomic_git_action
    def get_state(self, user=None, priority=None, no_cache=False, commit_hash=None) -> State:
        if user is None:
            user = self.master_user

        state = self.parse_state_from_commit(
            self.repo, user=user, commit_hash=commit_hash, is_master=user == self.master_user, client=self
        )

        # NOTE: there might be a race between get_state(no_cache=True) in
        # Client and get_state(...) from all_states() in Controller which uses
        # the cache. That race happens when we have a repository with a lot of
        # artifacts to retrieve. As the cache is using a defaultdict() we will
        # get an empty state back when querying from the cache, and we always
        # get this empty state as we don't update the cache.
        if no_cache or not self.cache.get_state(user):
            self.cache.set_state(state, user=user)

        return state

    @property
    def has_remote(self):
        """
        If there is a remote configured for our local repo.

        :return:    True if there is a remote, False otherwise.
        """
        return self.remote and self.remote in self.repo.remotes.names() and bool(self.repo.remotes[self.remote])


    def all_states(self, before_ts: int = None) -> Iterable[State]:
        states = list()
        # promises users in the event of inability to get new users
        users = self.users(no_cache=True) or self.users()
        if not users:
            l.critical("Failed to get users from current project. Report me if possible.")
            return {}

        usernames = [u.name for u in users]
        username_to_commit = {}
        if before_ts:
            username_to_commit = self.find_commits_before_ts(self.repo, before_ts, usernames)

        for username in usernames:
            commit_hash = username_to_commit.get(username, None)
            state = self.get_state(
                user=username, priority=SchedSpeed.FAST, commit_hash=commit_hash, no_cache=(commit_hash is not None)
            )

            # NOTE: It can happen that state is None when the state is
            # retrieved from cache and it has not been totally initialized yet
            # because of defaultdict() used in cache. We should filter out this
            # bogus entries
            if state:
                states.append(state)

        return states

    def find_commits_before_ts(self, repo: pygit2.Repository, ts: int, users: list[str]):
        ref_dict = self._get_best_branch_references(repo, force_local=True)
        best_commits = {}
        for user_name, ref in ref_dict.items():
            if user_name not in users:
                continue

            commits = list(repo.walk(ref))
            reverse_sorted_commits = sorted(commits, key=lambda x: x.commit.commit_time, reverse=True)
            for commit in reverse_sorted_commits:
                if commit.commit_time <= ts:
                    best_commits[user_name] = commit.hex
                    break

        return best_commits

    def commit_master_state(self, commit_msg=None) -> int:
        # attempt to commit dirty files in a update phase
        total_commits = 0
        for i in range(self._commit_batch_size):
            if self.cache.queued_master_state_changes.empty():
                break

            state = self.cache.queued_master_state_changes.get()
            self._commit_state(
                state,
                msg=commit_msg or state.last_commit_msg,
                no_checkout=i > 0
            )
            total_commits += 1

        self.cache._master_state._dirty = False
        return total_commits

    def commit_and_update_states(self, commit_msg=None):
        """
        Update both the local and remote repo knowledge of files through pushes/pulls and commits
        in the case of dirty files.
        """
        l.debug("Commit and update states")
        commit_num = self.commit_master_state(commit_msg=commit_msg)
        did_pull = False
        did_push = False

        # do a pull if there is a remote repo connected
        self.last_pull_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.has_remote and self.pull_on_update:
            did_pull = True
            self._pull()

        self.last_push_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.has_remote and self.push_on_update:
            did_push = True
            self._push()

        l.debug(f"Commit {commit_num} times, pull: {did_pull}, push: {did_push}")

    #
    # Git Backend
    #

    @atomic_git_action
    def _commit_state(self, state, msg=None, priority=None, no_checkout=False):
        msg = msg or self.DEFAULT_COMMIT_MSG
        if self.master_user != state.user:
            raise ExternalUserCommitError(f"User {self.master_user} is not allowed to commit to user {state.user}")

        if not no_checkout:
            self._checkout_to_master_user()

        # Dump state to index
        index = self.repo.index
        state.dump(index)

        # Stage changes
        index.add_all()
        index.write()

        # Create commit if there are changes
        try:
            head = self.repo.head
            parent = [head.target]
        except pygit2.GitError:
            # This can happen on first commit
            parent = []

        tree = index.write_tree()
        author = pygit2.Signature(state.user, f'{state.user}@binsync.auto.com')
        self.repo.create_commit('HEAD', author, author, msg, tree, parent)
        self._last_commit_time = datetime.datetime.now(tz=datetime.timezone.utc)
        state._dirty = False

    @atomic_git_action
    def _pull(self, priority=SchedSpeed.AVERAGE):
        """
        Pull changes from the remote side.

        :return:    None
        """
        self.last_pull_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        try:
            remote = self.repo.remotes[self.remote]
            remote.fetch()
            self._last_pull_time = datetime.datetime.now(tz=datetime.timezone.utc)
            self.active_remote = True

            # Merge changes
            for branch in self.repo.branches:
                if "HEAD" in branch:
                    continue
                try:
                    ref = self.repo.lookup_reference(f'refs/heads/{branch}')
                    remote_ref = self.repo.lookup_reference(f'refs/remotes/{self.remote}/{branch}')
                    if not ref or not remote_ref:
                        continue
                        
                    self.repo.checkout(ref, strategy=pygit2.GIT_CHECKOUT_FORCE)
                    self.repo.merge(remote_ref.target)
                    if self.repo.index.conflicts:
                        self.repo.state_cleanup()
                        continue
                    tree = self.repo.index.write_tree()
                    author = pygit2.Signature('BinSync', 'binsync@auto.com')
                    try:
                        head = self.repo.head
                        parents = [head.target, remote_ref.target]
                    except pygit2.GitError:
                        parents = [remote_ref.target]
                    self.repo.create_commit('HEAD', author, author, f"Merge {branch}", tree, parents)
                except (KeyError, ValueError, pygit2.GitError):
                    continue

        except Exception as e:
            l.debug(f"Pull failed: {e}")
            self.active_remote = False

        self._update_cache()

    @atomic_git_action
    def _push(self, print_error=False, priority=SchedSpeed.AVERAGE):
        """
        Push local changes to the remote side.

        :return:    None
        """
        self.last_push_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        self._checkout_to_master_user()
        try:
            remote = self.repo.remotes[self.remote]
            remote.push([f'refs/heads/{BINSYNC_ROOT_BRANCH}', f'refs/heads/{self.user_branch_name}'])
            self._last_push_time = datetime.datetime.now(tz=datetime.timezone.utc)
            #l.debug("Push completed successfully at %s", self._last_push_ts)
            self.active_remote = True
        except Exception as e:
            l.debug(f"Push failed: {e}")
            self.active_remote = False

    #
    # Git Updates
    #

    def _localize_remote_branches(self):
        """
        Looks up all the remote refrences on the server and attempts to make them a tracked local
        branch.

        @return:
        """
        # get all remote branches
        try:
            if self.remote not in self.repo.remotes:
                return
            remote_branches = self.repo.remotes[self.remote].refs
        except (ValueError, KeyError):
            return

        # track any remote we are not already tracking
        local_branches = set(b.name for b in self.repo.branches)
        for branch in remote_branches:
            # exclude head commit
            if "HEAD" in branch.name:
                continue

            # attempt to localize the remote name
            try:
                local_name = re.findall(f"({self.remote}/)(.*)", branch.name)[0][1]
            except IndexError:
                continue

            # never try to track things already tracked
            if local_name in local_branches:
                continue

            try:
                self.repo.create_branch(local_name, self.repo[branch.target])
            except pygit2.GitError:
                continue

    def _checkout_to_master_user(self):
        """
        Ensure the repo is in the proper branch for current user.

        :return: bool
        """
        ref = self.repo.lookup_reference(f'refs/heads/{self.user_branch_name}')
        self.repo.checkout(ref, strategy=pygit2.GIT_CHECKOUT_FORCE)

    def shutdown(self):
        if hasattr(self, "repo"):
            del self.repo

        self.scheduler.stop_worker_thread()

        if self.repo_lock is not None:
            self.repo_lock.release()
            # force delete it!
            if self._repo_lock_path.exists():
                self._repo_lock_path.unlink(missing_ok=True)

    def _get_best_branch_references(self, repo, force_local=False):
        candidates = {}
        for ref_name in repo.references:  # type: str
            if f'{BINSYNC_BRANCH_PREFIX}/' not in ref_name:
                continue

            user_name = ref_name.split('/')[-1]
            branch_name = f"{BINSYNC_BRANCH_PREFIX}/{user_name}"
            ref = repo.references[ref_name]
            if force_local:
                if self._is_remote_ref(ref):
                    continue
            elif branch_name in candidates:
                # if the candidate exists, and the new one is not remote, don't replace it
                if not self._is_remote_ref(ref):
                    continue

            candidates[branch_name] = ref
        return candidates

    def _get_stored_hash(self):
        ref = self.repo.lookup_reference(f'refs/heads/{BINSYNC_ROOT_BRANCH}')
        tree = self.repo[ref.target].tree
        try:
            blob = self.repo[tree["binary_hash"].id]
            return blob.data.decode().strip()
        except KeyError:
            return None

    @staticmethod
    def _is_remote_ref(ref):
        return ref.name.startswith("refs/remotes/")

    @staticmethod
    def list_files_in_tree(tree):
        """
        Lists all the files in a repo at a given tree

        :param tree: A pygit2 Tree object
        """
        file_list = []
        stack = [(tree, '')]  # Each item is (tree, prefix)
        while len(stack) > 0:
            tree, prefix = stack.pop()
            # enumerate entries at this level
            for entry in tree:
                path = os.path.join(prefix, entry.name)
                if entry.type_str == 'tree':
                    stack.append((tree[entry.name], path))
                elif entry.type_str == 'blob':
                    file_list.append(path)
        return file_list

    @staticmethod
    def add_data(index: pygit2.Index, repo: pygit2.Repository, path: str, data: bytes):
        """
        Adds physical files to the database.

        WARNING: this function touches physical files in the Git Repo which can result in a race
        condition to modify a file while it is also being pushed. ONLY CALL THIS FUNCTION INSIDE
        A COMMIT_LOCK.

        @param index: The index to add the file to
        @param repo: The repository object
        @param path: The path to write to
        @param data: The data to write
        @return:
        """
        repo_path = repo.workdir
        fullpath = os.path.join(repo_path, path)
        os.makedirs(os.path.dirname(fullpath), exist_ok=True)
        with open(fullpath, "wb") as f:
            f.write(data)
        index.add(path)

    @staticmethod
    def remove_data(index: pygit2.Index, repo: pygit2.Repository, path: str):
        """
        Removes physical files from the database.

        WARNING: this function touches physical files in the Git Repo which can result in a race
        condition to modify a file while it is also being pushed. ONLY CALL THIS FUNCTION INSIDE
        A COMMIT_LOCK.

        @param index: The index to remove the file from
        @param repo: The repository object
        @param path: The path to remove
        @return:
        """
        repo_path = repo.workdir
        fullpath = os.path.join(repo_path, path)
        if os.path.exists(fullpath):
            os.remove(fullpath)
        try:
            # check if the file exists in the index before trying to remove it
            index[path]
            index.remove(path)
        except (KeyError, IOError):
            # file doesn't exist in index, which is fine
            pass

    @staticmethod
    def load_file_from_tree(tree, filename):
        try:
            blob = tree[filename]
            return blob.data.decode()
        except KeyError:
            return None

    @staticmethod
    def _get_tree(user, repo: pygit2.Repository, commit_hash=None):
        if commit_hash is None:
            options = [name for name in repo.references if name.endswith(f"{BINSYNC_BRANCH_PREFIX}/{user}")]
            if not options:
                raise ValueError(f'No such user "{user}" found in repository')
            ref = repo.references[options[0]]
            commit_hash = ref.target
            bct = repo[commit_hash].tree
        else:
            bct = repo[commit_hash].tree
        return bct

    #
    # Caching Functions
    #

    def _get_commits_for_users(self, repo: pygit2.Repository):
        ref_dict = self._get_best_branch_references(repo)

        # ignore the _root_ branch
        if BINSYNC_ROOT_BRANCH in ref_dict:
            del ref_dict[BINSYNC_ROOT_BRANCH]

        commit_dict = {
            branch_name: ref.commit.hex for branch_name, ref in ref_dict.items()
        }
        return commit_dict

    def check_cache_(self, f, **kwargs):
        if f.__qualname__ == self.get_state.__qualname__:
            cache_func = self.cache.get_state
            args = []
            if kwargs.get("user", None) is None:
                kwargs["user"] = self.master_user

        elif f.__qualname__ == self.users.__qualname__:
            cache_func = self.cache.users
            args = []
        else:
            return None

        item = cache_func(*args, **kwargs)

        return item

    def _set_cache(self, f, ret_value, **kwargs):
        if f.__qualname__ == self.get_state.__qualname__:
            set_func = self.cache.set_state
            args = []
            if kwargs.get("user", None) is None:
                kwargs["user"] = self.master_user
        elif f.__qualname__ == self.users.__qualname__:
            set_func = self.cache.set_users
            args = []
        else:
            return None

        set_func(ret_value, *args, **kwargs)

    def _update_cache(self):
        #l.debug(f"Updating cache commits for State Cache...")
        cache_dict = self._get_commits_for_users(self.repo)
        self.cache.clear_state_cache(cache_dict)

        cache_keys = [key for key in cache_dict.keys()]
        #l.debug(f"Updating branches on Users Cache...")
        branch_set = set(cache_keys)
        self.cache.clear_user_branch_cache(branch_set)

    def _load_toml_from_tree(self, tree, filename):
        """Load and parse TOML file from Git tree"""
        try:
            blob = self.repo[tree[filename].id]
            return toml.loads(blob.data.decode())
        except (KeyError, ValueError):
            return None


