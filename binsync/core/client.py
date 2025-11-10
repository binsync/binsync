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
import git
import git.exc

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
            try:
                temp_dir = tempfile.TemporaryDirectory()
            except Exception as e:
                l.error("Failed to create temporary directory for copy: %s", e)
            abs_path_str = str(Path(temp_dir.name).absolute())
            # skip git lock files
            shutil.copytree(
                self.repo_root,
                abs_path_str,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('.git/binsync.lock', '.git/index.lock')
            )
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
        # Release locks and stop threads before deleting temporary directories
        try:
            self.shutdown()
        finally:
            if self._temp_directory is not None:
                try:
                    self._temp_directory.cleanup()
                except PermissionError as e:
                    # log and ignore: Windows may still hold a handle briefly
                    l.warning("Temp cleanup skipped (PermissionError) for %s: %s", self._temp_directory.name, e)

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
            branch = next(o for o in self.repo.branches if o.name.endswith(self.user_branch_name))
        except StopIteration:
            branch = self.repo.create_head(self.user_branch_name, BINSYNC_ROOT_BRANCH)
        else:
            if branch.is_remote():
                branch = self.repo.create_head(self.user_branch_name)
        branch.checkout()

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

            self.repo: git.Repo = self.clone(remote_url, no_head_check=init_repo)

            if init_repo:
                if any(b.name == BINSYNC_ROOT_BRANCH for b in self.repo.branches):
                    raise Exception("Can't init this remote repo since a BinSync root already exists")

                self._setup_repo()
        else:
            try:
                self.repo = git.Repo(self.repo_root)

                # update view of remote branches (which may be new)
                self._localize_remote_branches()

                if init_repo:
                    raise Exception("Could not initialize repository - it already exists!")
                if not any(b.name == BINSYNC_ROOT_BRANCH for b in self.repo.branches):
                    raise Exception(f"This is not a BinSync repo - it must have a {BINSYNC_ROOT_BRANCH} branch.")
            except (git.NoSuchPathError, git.InvalidGitRepositoryError):
                if init_repo:
                    # case 3
                    self.repo = git.Repo.init(self.repo_root)
                    self._setup_repo()
                else:
                    raise Exception("Failed to connect or create a BinSync repo")

        stored = self._get_stored_hash()
        if stored != self.binary_hash:
            self.connection_warnings.append(ConnectionWarnings.HASH_MISMATCH)

        assert not self.repo.bare, "it should not be a bare repo"

        # If ignore_lock is set (e.g., temporary/copy clients), do not create a lock at all.
        # This avoids keeping a handle to .git/binsync.lock which can block temp dir cleanup on Windows.
        if self._ignore_lock:
            if self._repo_lock_path.exists():
                try:
                    self._repo_lock_path.unlink(missing_ok=True)
                except Exception:
                    pass
            self.repo_lock = None
            return self.repo

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
        # Ensure git identity is configured before making any commits
        self._ensure_git_identity()
        
        with open(os.path.join(self.repo_root, ".gitignore"), "w", encoding="utf-8") as f:
            f.write(".git/*\n")
        with open(os.path.join(self.repo_root, "binary_hash"), "w", encoding="utf-8") as f:
            f.write(self.binary_hash)
        self.repo.index.add([".gitignore", "binary_hash"])
        self.repo.index.commit("Root commit")
        self.repo.create_head(BINSYNC_ROOT_BRANCH)

    def _ensure_git_identity(self):
        """
        Ensures Git user identity is configured. If not configured, sets it up with 
        the master user name and a default email.
        """
        # Check if we've already configured identity for this session
        if hasattr(self, '_git_identity_configured'):
            return
            
        user_name = None
        user_email = None
        
        try:
            # Check if user.name and user.email are configured
            user_name = self.repo.config_reader().get_value('user', 'name', fallback=None)
            user_email = self.repo.config_reader().get_value('user', 'email', fallback=None)
            
            if user_name and user_email:
                self._git_identity_configured = True
                return  # Already configured
                
        except Exception:
            # Config doesn't exist or can't be read
            pass
        
        # Configure Git identity using the master user name
        with self.repo.config_writer() as git_config:
            if not user_name:
                git_config.set_value('user', 'name', self.master_user)
            if not user_email:
                git_config.set_value('user', 'email', f'{self.master_user}@binsync.local')
        
        l.info("Configured Git identity: %s <%s@binsync.local>", self.master_user, self.master_user)
        self._git_identity_configured = True

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
        repo = self.repo
        attempt_again = True
        attempted_fix = False
        users = list()
        force_local_users = False

        while attempt_again:
            attempt_again = False
            users = list()
            for ref in self._get_best_refs(repo, force_local=force_local_users).values():
                #l.debug(f"{ref} NAME: {ref.name}")
                try:
                    metadata = toml_file_to_dict(ref.commit.tree, "metadata.toml", client=self)
                    user = User.from_metadata(metadata)
                    users.append(user)
                except Exception as e:
                    #l.debug(f"Unable to load user {e}")
                    continue

            if not attempted_fix and not users:
                # attempt a fix once
                force_local_users = True
                attempt_again = True
                attempted_fix = True

        return users

    @staticmethod
    def parse_state_from_commit(repo: git.Repo, user=None, commit_hash=None, is_master=False, client=None) -> State:
        if user is None and commit_hash is None:
            raise ValueError("Must specify either a user or a commit hash")

        if user is not None and commit_hash is not None:
            raise ValueError("Cannot specify both user and commit_hash")

        #import remote_pdb;
        #remote_pdb.RemotePdb("localhost", 4444).set_trace()

        # Checkout to user branch or commit_hash
        checkout_ref = commit_hash or f"binsync/{user}"
        repo.git.checkout(checkout_ref)

        # Parse State object from repo path
        state = State(None)
        try:
            state = State.parse(
                Path(repo.working_tree_dir),
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
                l.critical("Invalid state for %s, dropping: %s", user, e)
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
    @atomic_git_action
    def has_remote(self, priority=SchedSpeed.FAST):
        """
        If there is a remote configured for our local repo.

        :return:    True if there is a remote, False otherwise.
        """
        return self.remote and any(r.name == self.remote for r in self.repo.remotes)

    def all_states(self, before_ts: int = None) -> Iterable[State]:
        states = list()
        # promises users in the event of inability to get new users
        users = self.users(no_cache=True) or self.users()
        if not users:
            l.critical("Failed to get users from current project. Report me if possible.")
            return {}

        usernames = []
        for u in users:
            # TODO: don't know why this is how it is... fix this later?
            usernames.append(u if isinstance(u, str) else u.name)

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

    def find_commits_before_ts(self, repo: git.Repo, ts: int, users: list[str]):
        ref_dict = self._get_best_refs(repo, force_local=True)
        best_commits = {}
        for user_name, ref in ref_dict.items():
            if user_name not in users:
                continue

            commits = list(repo.iter_commits(ref))
            reverse_sorted_commits = sorted(commits, key=lambda x: x.committed_date, reverse=True)
            for commit in reverse_sorted_commits:
                if commit.committed_date <= ts:
                    best_commits[user_name] = commit.hexsha
                    break

        return best_commits

    def commit_master_state(self, commit_msg=None) -> int:
        # Attempt to commit dirty files in a update phase.
        # Similar to other parts of the code base, an empty state can make it in here in the very first iteration
        # of the client. We just ignore that state.
        total_commits = 0
        for i in range(self._commit_batch_size):
            if self.cache.queued_master_state_changes.empty():
                break

            state = self.cache.queued_master_state_changes.get()
            if state:
                self._commit_state(
                    state,
                    msg=commit_msg or state.last_commit_msg,
                )
                total_commits += 1

        if self.cache._master_state:
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

        l.debug("Commit %d times, pull: %s, push: %s", commit_num, did_pull, did_push)

    #
    # Git Backend
    #

    @atomic_git_action
    def _commit_state(self, state, msg=None, priority=None):
        msg = msg or self.DEFAULT_COMMIT_MSG
        if self.master_user != state.user:
            raise ExternalUserCommitError(f"User {self.master_user} is not allowed to commit to user {state.user}")

        
        self._checkout_to_master_user()
        state.dump(str(self.repo_root))

        # Add files using git commands
        self.repo.git.add('.')
        self.repo.git.add(update=True)

        # Check if there are changes to commit
        if not self.repo.git.diff("HEAD", name_only=True):
            return

        # Commit using git command directly
        try:
            self.repo.git.commit(m=msg)
            # Get the latest commit
            commit = self.repo.head.commit
        except Exception as e:
            l.warning("Internal Git Commit Error: %s", e)
            return

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
            env = self.ssh_agent_env()
        except Exception:
            return

        with self.repo.git.custom_environment(**env):
            # dangerous remote operations happen here
            try:
                self._localize_remote_branches()
                # Pull from remote without checking out to __root__ branch
                # Use git fetch instead of pull to avoid tracking branch issues
                self.repo.git.fetch("--all")
                self._last_pull_time = datetime.datetime.now(tz=datetime.timezone.utc)
                self.active_remote = True
            except Exception as e:
                l.error("Pull exception %s", e)
                self.active_remote = False

        if not self.active_remote:
            return

        # preform a merge on each branch
        for branch in self.repo.branches:
            if "HEAD" in branch.name:
                continue

            self.repo.git.checkout(branch)
            try:
                self.repo.git.merge()
            except Exception as e:
                #l.debug(f"Failed to merge on {branch} with {e}")
                pass

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
            env = self.ssh_agent_env()
            with self.repo.git.custom_environment(**env):
                self.repo.remotes[self.remote].push(BINSYNC_ROOT_BRANCH)
                self.repo.remotes[self.remote].push(self.user_branch_name)
            self._last_push_time = datetime.datetime.now(tz=datetime.timezone.utc)
            #l.debug("Push completed successfully at %s", self._last_push_ts)
            self.active_remote = True
        except git.exc.GitCommandError as ex:
            self.active_remote = False
            l.error("Failed to push b/c %s", ex)

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
            remote_branches = self.repo.remote().refs
        except ValueError:
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
                self.repo.git.checkout('--track', branch.name)
            except git.GitCommandError as e:
                continue



    def ssh_agent_env(self):
        if self.ssh_agent_pid is not None and self.ssh_auth_sock is not None:
            env = {
                'SSH_AGENT_PID': str(self.ssh_agent_pid),
                'SSH_AUTH_SOCK': str(self.ssh_auth_sock),
            }
        else:
            env = { }
        return env

    def clone(self, remote_url, no_head_check=False):
        """
        Checkout from a remote_url to a local path specified by self.local_root.

        :param str remote_url:  The URL of the Git remote.
        :return:                None
        """

        env = self.ssh_agent_env()
        repo = git.Repo.clone_from(remote_url, self.repo_root, env=env)

        if no_head_check:
            return repo

        try:
            repo.create_head(BINSYNC_ROOT_BRANCH, f'{self.remote}/{BINSYNC_ROOT_BRANCH}')
        except git.BadName:
            raise Exception(f"This is not a binsync repo - it must have a {BINSYNC_ROOT_BRANCH} branch")

        return repo

    def _checkout_to_master_user(self):
        """
        Ensure the repo is in the proper branch for current user.

        :return: bool
        """
        self.repo.git.checkout(self.user_branch_name)

    @staticmethod
    def discover_ssh_agent(ssh_agent_cmd):
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
        if hasattr(self, "repo"):
            self.repo.close()
            del self.repo

        self.scheduler.stop_worker_thread()

        if self.repo_lock is not None:
            # release the lock and remove the lock file
            try:
                self.repo_lock.release()
            except Exception:
                l.error("Failed to release repo lock")
            # force delete it!
            try:
                if self._repo_lock_path.exists():
                    self._repo_lock_path.unlink(missing_ok=True)
            except PermissionError as e:
                l.warning("Failed to unlink repo lock file %s: %s", self._repo_lock_path, e)

    def _get_best_refs(self, repo, force_local=False):
        candidates = {}
        for ref in repo.refs:  # type: git.Reference
            if f'{BINSYNC_BRANCH_PREFIX}/' not in ref.name:
                continue

            branch_name = ref.name.split("/")[-1]
            if force_local:
                if ref.is_remote():
                    continue
            else:
                if branch_name in candidates:
                    # if the candidate exists, and the new one is not remote, don't replace it
                    if not ref.is_remote() or ref.remote_name != self.remote:
                        continue

            candidates[branch_name] = ref
        return candidates

    def _get_stored_hash(self):
        branch = [ref for ref in self.repo.refs if ref.name.endswith(BINSYNC_ROOT_BRANCH)][0]
        return branch.commit.tree["binary_hash"].data_stream.read().decode('utf-8').strip("\n")

    @staticmethod
    def list_files_in_tree(base_tree: git.Tree):
        """
        Lists all the files in a repo at a given tree

        :param commit: A gitpython Tree object
        """
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
    def add_data(index: git.IndexFile, path: str, data: bytes):
        """
        Adds physical files to the database.

        WARNING: this function touches physical files in the Git Repo which can result in a race
        condition to modify a file while it is also being pushed. ONLY CALL THIS FUNCTION INSIDE
        A COMMIT_LOCK.

        @param index:
        @param path:
        @param data:
        @return:
        """
        fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
        pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
        with open(fullpath, 'wb') as fp:
            fp.write(data)
        index.add([fullpath])

    @staticmethod
    def remove_data(index: git.IndexFile, path: str):
        fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
        pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
        index.remove([fullpath], working_tree=True)

    @staticmethod
    def load_file_from_tree(tree: git.Tree, filename):
        try:
            return tree[filename].data_stream.read().decode('utf-8')
        except KeyError:
            return None

    @staticmethod
    def _get_tree(user, repo: git.Repo, commit_hash=None):
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
    # Caching Functions
    #

    def _get_commits_for_users(self, repo: git.Repo):
        ref_dict = self._get_best_refs(repo)

        # ignore the _root_ branch
        if BINSYNC_ROOT_BRANCH in ref_dict:
            del ref_dict[BINSYNC_ROOT_BRANCH]

        commit_dict = {
            branch_name: ref.commit.hexsha for branch_name, ref in ref_dict.items()
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
        cache_dict = self._get_commits_for_users(git.Repo(self.repo_root))
        self.cache.clear_state_cache(cache_dict)

        cache_keys = [key for key in cache_dict.keys()]
        #l.debug(f"Updating branches on Users Cache...")
        branch_set = set(cache_keys)
        self.cache.clear_user_branch_cache(branch_set)


