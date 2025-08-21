import logging
import pathlib
import os
import datetime
import shutil
from typing import Iterable, Optional
from pathlib import Path
import tempfile

from binsync.core.user import User
from binsync.configuration import BinSyncBSConfig, ProjectData
from binsync.core.errors import ExternalUserCommitError, MetadataNotFoundError
from binsync.core.state import State, toml_file_to_dict
from binsync.core.scheduler import Scheduler, Job, SchedSpeed
from binsync.core.cache import Cache
from binsync.core.git_backend import GitBackend

l = logging.getLogger(__name__)
BINSYNC_BRANCH_PREFIX = 'binsync'
BINSYNC_ROOT_BRANCH = f'{BINSYNC_BRANCH_PREFIX}/__root__'


class ConnectionWarnings:
    HASH_MISMATCH = 0


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
        Things like committing, pulling, and pushing all happen on the client level.

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
        self.pull_on_update = pull_on_update
        self.push_on_update = push_on_update
        self.commit_on_update = commit_on_update
        self._temp_directory: tempfile.TemporaryDirectory | None = temp_directory
        
        # timestamps
        self._commit_interval = commit_interval
        self._commit_batch_size = commit_batch_size
        self.last_push_attempt_time = None  # type: datetime.datetime
        self.last_pull_attempt_time = None  # type: datetime.datetime
        self._last_commit_time = None # type: datetime.datetime
        
        # Initialize Git backend
        try:
            self.git_backend = GitBackend(
                master_user=master_user,
                repo_root=repo_root,
                binary_hash=binary_hash,
                remote=remote,
                remote_url=remote_url,
                ssh_agent_pid=ssh_agent_pid,
                ssh_auth_sock=ssh_auth_sock,
                init_repo=init_repo,
                ignore_lock=ignore_lock,
            )
        except Exception as e:
            # Provide helpful error messages for common issues
            error_msg = str(e).lower()
            if "authentication" in error_msg:
                l.error("Git authentication failed. Run 'python binsync_auth_check.py' to diagnose the issue.")
            elif "connection refused" in error_msg:
                l.error("Network connection failed. Check your internet connection.")
            elif "repository not found" in error_msg:
                l.error("Repository not found. Check the repository URL and your access permissions.")
            raise
        
        # Legacy compatibility properties
        self.master_user = self.git_backend.master_user
        self.repo_root = self.git_backend.repo_root
        self.binary_hash = self.git_backend.binary_hash
        self.remote = self.git_backend.remote
        self.repo = self.git_backend.repo
        self.connection_warnings = []
        self.active_remote = self.git_backend.active_remote
        
        # job scheduler and cache
        self.cache = Cache(master_user=master_user)
        self.scheduler = Scheduler(name="GitScheduler")
        self.scheduler.start_worker_thread()
        
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
            ssh_agent_pid=self.git_backend.ssh_agent_pid,
            ssh_auth_sock=self.git_backend.ssh_auth_sock,
            push_on_update=self.pull_on_update,
            pull_on_update=self.pull_on_update,
            commit_on_update=self.commit_on_update,
            temp_directory=temp_dir,
            ignore_lock=self.git_backend._ignore_lock or copy_files,
            init_user_branch=not copy_files,
        )

    def __del__(self):
        if self._temp_directory is not None:
            self._temp_directory.cleanup()

        self.shutdown()

    # Legacy initialization methods now handled by GitBackend

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
        return self.git_backend.last_push_ts

    @property
    def last_pull_ts(self):
        return self.git_backend.last_pull_ts

    @property
    def last_commit_ts(self):
        return self.git_backend.last_commit_ts

    @property
    def user_branch_name(self):
        return self.git_backend.user_branch_name

    #
    # Simplified Public API (no more atomic actions)
    #

    def users(self, priority=None, no_cache=False) -> Iterable[User]:
        """Get list of all users, with caching support"""
        if not no_cache:
            # Check cache first
            cached_users = self.cache.users()
            if cached_users:
                return cached_users
        
        # Get users from Git backend
        users = self.git_backend.users()
        
        # Update cache
        self.cache.set_users(users)
        return users
        
    def refresh_remote_users(self):
        """Force refresh of remote users by fetching and localizing remote branches"""
        return self.git_backend.refresh_remote_users()
    
    def detect_repo_corruption(self):
        """Detect repository corruption"""
        return self.git_backend.detect_repo_corruption()

    @staticmethod
    def parse_state_from_commit(repo, user=None, commit_hash=None, is_master=False, client=None) -> State:
        """Static method for parsing state from commit - delegated to GitBackend"""
        if hasattr(client, 'git_backend'):
            return client.git_backend._parse_state_from_commit(user=user, commit_hash=commit_hash, is_master=is_master)
        else:
            # Fallback for compatibility
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
                    state = State(user, client=client)
            except Exception as e:
                if is_master:
                    raise
                else:
                    l.critical(f"Invalid state for {user}, dropping: {e}")
                    state = State(user)
            return state

    def get_state(self, user=None, priority=None, no_cache=False, commit_hash=None) -> State:
        """Get state for a user, with caching support"""
        if user is None:
            user = self.master_user

        # Check cache first if not no_cache
        if not no_cache:
            cached_state = self.cache.get_state(user=user)
            if cached_state and not commit_hash:  # Don't use cache for specific commits
                return cached_state

        # Get state from Git backend
        state = self.git_backend.get_state(user=user, commit_hash=commit_hash)

        # Update cache
        if not commit_hash:  # Only cache current states, not historical ones
            self.cache.set_state(state, user=user)

        return state

    @property
    def has_remote(self, priority=SchedSpeed.FAST):
        """Check if there is a remote configured for our local repo."""
        return self.git_backend.has_remote

    def all_states(self, before_ts: int = None) -> Iterable[State]:
        """Get all states for all users"""
        states = list()
        users = self.users(no_cache=True) or self.users()
        if not users:
            l.critical("Failed to get users from current project. Report me if possible.")
            return {}

        usernames = []
        for u in users:
            usernames.append(u if isinstance(u, str) else u.name)

        username_to_commit = {}
        if before_ts:
            username_to_commit = self.git_backend.find_commits_before_ts(before_ts, usernames)

        for username in usernames:
            commit_hash = username_to_commit.get(username, None)
            state = self.get_state(
                user=username, priority=SchedSpeed.FAST, commit_hash=commit_hash, no_cache=(commit_hash is not None)
            )

            if state:
                states.append(state)

        return states

    def find_commits_before_ts(self, repo, ts: int, users: list[str]):
        """Find commits before timestamp - delegated to GitBackend"""
        return self.git_backend.find_commits_before_ts(ts, users)

    def commit_master_state(self, commit_msg=None) -> int:
        """Commit master state changes"""
        total_commits = 0
        for i in range(self._commit_batch_size):
            if self.cache.queued_master_state_changes.empty():
                break

            state = self.cache.queued_master_state_changes.get()
            if self.git_backend.commit_state(state, commit_msg or state.last_commit_msg):
                total_commits += 1

        self.cache._master_state._dirty = False
        return total_commits

    def commit_and_update_states(self, commit_msg=None):
        """Update both local and remote repo knowledge through commits/pulls/pushes"""
        l.debug("Commit and update states")
        commit_num = self.commit_master_state(commit_msg=commit_msg)
        did_pull = False
        did_push = False

        # do a pull if there is a remote repo connected
        self.last_pull_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.has_remote and self.pull_on_update:
            did_pull = self.git_backend.pull()

        self.last_push_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.has_remote and self.push_on_update:
            did_push = self.git_backend.push()

        l.debug(f"Commit {commit_num} times, pull: {did_pull}, push: {did_push}")

    #
    # Git Backend Delegated Methods
    #

    def _commit_state(self, state, msg=None, priority=None, no_checkout=False):
        """Commit state - simplified version delegated to GitBackend"""
        return self.git_backend.commit_state(state, msg)

    def _pull(self, priority=SchedSpeed.AVERAGE):
        """Pull changes from remote - delegated to GitBackend"""
        return self.git_backend.pull()

    def _push(self, print_error=False, priority=SchedSpeed.AVERAGE):
        """Push changes to remote - delegated to GitBackend"""
        return self.git_backend.push()

    def ssh_agent_env(self):
        """Get SSH agent environment variables"""
        if self.git_backend.ssh_agent_pid is not None and self.git_backend.ssh_auth_sock is not None:
            env = {
                'SSH_AGENT_PID': str(self.git_backend.ssh_agent_pid),
                'SSH_AUTH_SOCK': str(self.git_backend.ssh_auth_sock),
            }
        else:
            env = {}
        return env

    def clone(self, remote_url, no_head_check=False):
        """Clone repository - delegated to GitBackend"""
        return self.git_backend._clone_repository(remote_url, no_head_check)

    def _checkout_to_master_user(self):
        """Checkout to master user branch - delegated to GitBackend"""
        return self.git_backend._checkout_to_master_user()

    @staticmethod
    def discover_ssh_agent(ssh_agent_cmd):
        """Discover SSH agent (unchanged from original)"""
        import subprocess
        import re
        
        proc = subprocess.Popen(ssh_agent_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")

        if proc.returncode != 0 or stderr:
            raise RuntimeError("Failed to discover SSH agent by running command %s.\n"
                               "Return code: %d.\n"
                               "stderr: %s" % (
                ssh_agent_cmd,
                proc.returncode,
                stderr,
            ))

        # parse output
        m = re.search(r"Found ssh-agent at (\d+)", stdout)
        if m is None:
            print("Failed to find 'Found ssh-agent at'")
            m = re.search(r"SSH_AGENT_PID=(\d+);", stdout)
            if m is None:
                print("Failed to find SSH_AGENT_PID")
                return None, None
            print("Found SSH_AGENT_PID")
            ssh_agent_pid = int(m.group(1))
            m = re.search("SSH_AUTH_SOCK=(.*?);", stdout)
            if m is None:
                print("Failed to find SSH_AUTH_SOCK")
                return None, None
            print("Found SSH_AGENT_SOCK")
            ssh_agent_sock = m.group(1)
        else :
            print("Found ssh-agent at")
            ssh_agent_pid = int(m.group(1))
            m = re.search(r"Found ssh-agent socket at ([^\s]+)", stdout)
            if m is None:
                print("Failed to find 'Found ssh-agent socket at'")
                return None, None
            print("Found ssh-agent socket at")
            ssh_agent_sock = m.group(1)

        return ssh_agent_pid, ssh_agent_sock

    def shutdown(self):
        """Clean up resources"""
        if hasattr(self, "git_backend"):
            self.git_backend.shutdown()

        if hasattr(self, "scheduler"):
            self.scheduler.stop_worker_thread()

    def _get_best_refs(self, repo, force_local=False):
        """Get best refs - delegated to existing logic for compatibility"""
        candidates = {}
        for ref in repo.refs:
            if f'{BINSYNC_BRANCH_PREFIX}/' not in ref.name:
                continue

            branch_name = ref.name.split("/")[-1]
            if force_local:
                if ref.is_remote():
                    continue
            else:
                if branch_name in candidates:
                    if not ref.is_remote() or ref.remote_name != self.remote:
                        continue

            candidates[branch_name] = ref
        return candidates

    def _get_stored_hash(self):
        """Get stored hash - delegated to GitBackend"""
        return self.git_backend._get_stored_hash(self.git_backend.repo)

    @staticmethod
    def list_files_in_tree(base_tree):
        """List files in tree - unchanged from original (GitPython compatibility)"""
        file_list = []
        stack = [base_tree]
        while len(stack) > 0:
            tree = stack.pop()
            # enumerate blobs (files) at this level
            for b in tree.blobs:
                file_list.append(b.path)
            for subtree in tree.trees:
                stack.append(subtree)

        return file_list

    @staticmethod
    def add_data(index, path: str, data: bytes):
        """Add data to index - delegated to GitBackend"""
        GitBackend.add_data(index, path, data)

    @staticmethod
    def remove_data(index, path: str):
        """Remove data from index - delegated to GitBackend"""
        GitBackend.remove_data(index, path)

    @staticmethod
    def load_file_from_tree(tree, filename):
        """Load file from tree - delegated to GitBackend"""
        return GitBackend.load_file_from_tree(tree, filename)

    @staticmethod
    def _get_tree(user, repo, commit_hash=None):
        """Get tree from user/commit - unchanged compatibility method"""
        if commit_hash is None:
            options = [ref for ref in repo.refs if ref.name.endswith(f"{BINSYNC_BRANCH_PREFIX}/{user}")]
            if not options:
                raise ValueError(f'No such user "{user}" found in repository')

            # find the latest commit for the specified user!
            best = max(options, key=lambda ref: ref.commit.authored_date)
            bct = best.commit.tree
        else:
            bct = repo.commit(commit_hash).tree

        return bct

    #
    # Caching Functions (simplified)
    #

    def _get_commits_for_users(self, repo):
        """Get commits for users - simplified version"""
        ref_dict = self._get_best_refs(repo)

        # ignore the _root_ branch
        if BINSYNC_ROOT_BRANCH in ref_dict:
            del ref_dict[BINSYNC_ROOT_BRANCH]

        commit_dict = {
            branch_name: ref.commit.hexsha for branch_name, ref in ref_dict.items()
        }
        return commit_dict

    def check_cache_(self, f, **kwargs):
        """Check cache - simplified version"""
        if f.__name__ == 'get_state':
            args = []
            if kwargs.get("user", None) is None:
                kwargs["user"] = self.master_user
            return self.cache.get_state(*args, **kwargs)
        elif f.__name__ == 'users':
            return self.cache.users()
        else:
            return None

    def _set_cache(self, f, ret_value, **kwargs):
        """Set cache - simplified version"""
        if f.__name__ == 'get_state':
            args = []
            if kwargs.get("user", None) is None:
                kwargs["user"] = self.master_user
            self.cache.set_state(ret_value, *args, **kwargs)
        elif f.__name__ == 'users':
            self.cache.set_users(ret_value)

    def _update_cache(self):
        """Update cache - simplified version"""
        cache_dict = self._get_commits_for_users(self.repo)
        self.cache.clear_state_cache(cache_dict)

        cache_keys = [key for key in cache_dict.keys()]
        branch_set = set(cache_keys)
        self.cache.clear_user_branch_cache(branch_set)

