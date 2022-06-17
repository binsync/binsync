import time
import threading
import os
import subprocess
import re
import datetime
import logging
import pathlib
from typing import Optional, Iterable

import git
import git.exc
import filelock

from .data import User, Function, Struct, Patch
from .state import State
from .errors import MetadataNotFoundError, ExternalUserCommitError

l = logging.getLogger(__name__)
BINSYNC_BRANCH_PREFIX = 'binsync'
BINSYNC_ROOT_BRANCH = f'{BINSYNC_BRANCH_PREFIX}/__root__'


class ConnectionWarnings:
    HASH_MISMATCH = 0


class StateContext(object):
    def __init__(self, client, state, locked=False):
        self.client = client
        self.state = state
        self.locked = locked

    def __enter__(self):
        if self.locked:
            self.client.commit_lock.acquire()
        return self.state

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.locked:
            self.client.commit_lock.release()
        self.client.commit_state(state=self.state)


class Client:
    def __init__(
        self,
        master_user: str,
        repo_root: str,
        binary_hash: bytes,
        remote: str = "origin",
        commit_interval: int = 10,
        init_repo: bool = False,
        remote_url: Optional[str] = None,
        ssh_agent_pid: Optional[int] = None,
        ssh_auth_sock: Optional[str] = None
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
        self.master_user = master_user
        self.repo_root = repo_root
        self.binary_hash = binary_hash
        self.remote = remote
        self.repo = None
        self.repo_lock = None

        if master_user.endswith('/') or '__root__' in master_user:
            raise Exception(f"Bad username: {master_user}")

        # ssh-agent info
        self.ssh_agent_pid = ssh_agent_pid  # type: int
        self.ssh_auth_sock = ssh_auth_sock  # type: str
        self.connection_warnings = []

        self.repo = self._get_binsync_repo(remote_url, init_repo)

        # check out the appropriate branch
        try:
            branch = next(o for o in self.repo.branches if o.name.endswith(self.user_branch_name))
        except StopIteration:
            branch = self.repo.create_head(self.user_branch_name, BINSYNC_ROOT_BRANCH)
        else:
            if branch.is_remote():
                branch = self.repo.create_head(self.user_branch_name)
        branch.checkout()

        self._commit_interval = commit_interval
        self._updater_thread = None
        self._last_push_at = None  # type: datetime.datetime
        self.last_push_attempt_at = None  # type: datetime.datetime
        self._last_pull_at = None  # type: datetime.datetime
        self.last_pull_attempt_at = None  # type: datetime.datetime

        # timestamps
        self._last_commit_ts = 0

        self.state = None
        self.commit_lock = threading.Lock()

    def __del__(self):
        if self.repo_lock is not None:
            self.repo_lock.release()

    def _get_binsync_repo(self, remote_url, init_repo):
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

        :param remote_url:
        :param init_repo:
        :return:
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
                self.update_remote_view()

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
                    raise Exception(f"Failed to connect or create a BinSync repo")

        stored = self._get_stored_hash()
        if stored != self.binary_hash:
            self.connection_warnings.append(ConnectionWarnings.HASH_MISMATCH)

        assert not self.repo.bare, "it should not be a bare repo"

        self.repo_lock = filelock.FileLock(self.repo_root + "/.git/binsync.lock")
        try:
            self.repo_lock.acquire(timeout=0)
        except filelock.Timeout as e:
            raise Exception("Can only have one binsync client touching a local repository at once.\n"
                            "If the previous client crashed, you need to delete " + self.repo_root +
                            "/.git/binsync.lock") from e

        return self.repo

    def update_remote_view(self):
        """
        Updates PyGits view of remote references in the repo by both trying to get remote references
        and checking out local ones.
        """
        # get all remote branches
        try:
            branches = self.repo.remote().refs
        except ValueError:
            return

        # track any remote we are not already tracking
        for branch in branches:
            if "HEAD" in branch.name:
                continue

            try:
                self.repo.git.checkout('--track', branch.name)
            except git.GitCommandError as e:
                pass

    @property
    def user_branch_name(self):
        return f"{BINSYNC_BRANCH_PREFIX}/{self.master_user}"

    @property
    def has_remote(self):
        """
        If there is a remote configured for our local repo.

        :return:    True if there is a remote, False otherwise.
        """
        return self.remote and self.repo.remotes and any(r.name == self.remote for r in self.repo.remotes)

    @property
    def last_update_timestamp(self):
        return self._last_commit_ts

    def ssh_agent_env(self):
        if self.ssh_agent_pid is not None and self.ssh_auth_sock is not None:
            env = {
                'SSH_AGENT_PID': str(self.ssh_agent_pid),
                'SSH_AUTH_SOCK': str(self.ssh_auth_sock),
            }
        else:
            env = { }
        return env

    def add_remote(self, name, remote_url):
        """
        Add a remote to the local repo.

        :param name:
        :param remote_url:
        :return:
        """

        self.repo.create_remote(name, url=remote_url)

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

    def checkout_to_master_user(self):
        """
        Ensure the repo is in the proper branch for current user.

        :return: bool
        """
        self.repo.git.checkout(self.user_branch_name)

    def pull(self, print_error=False):
        """
        Pull changes from the remote side.

        :return:    None
        """
        with self.commit_lock:
            self.last_pull_attempt_at = datetime.datetime.now()

            self.checkout_to_master_user()
            if self.has_remote:
                try:
                    env = self.ssh_agent_env()
                    with self.repo.git.custom_environment(**env):
                        self.repo.remotes[self.remote].pull()
                    self._last_pull_at = datetime.datetime.now()
                    l.debug("Pull completed successfully at %s", self._last_pull_at)
                except git.exc.GitCommandError as ex:
                    if print_error:
                        print("Failed to pull from remote \"%s\".\n"
                              "\n"
                              "Git error: %s." % (
                                  self.remote,
                                  str(ex)
                              ))

    def push(self, print_error=False):
        """
        Push local changes to the remote side.

        :return:    None
        """
        self.last_push_attempt_at = datetime.datetime.now()

        self.checkout_to_master_user()
        if self.has_remote:
            try:
                env = self.ssh_agent_env()
                with self.repo.git.custom_environment(**env):
                    self.repo.remotes[self.remote].push(BINSYNC_ROOT_BRANCH)
                    self.repo.remotes[self.remote].push(self.user_branch_name)
                self._last_push_at = datetime.datetime.now()
                l.debug("Push completed successfully at %s", self._last_push_at)
            except git.exc.GitCommandError as ex:
                if print_error:
                    print("Failed to push to remote \"%s\".\n"
                          "Did you setup %s/master as the upstream of the local master branch?\n"
                          "\n"
                          "Git error: %s." % (
                        self.remote,
                        self.remote,
                        str(ex)
                    ))

    def users(self) -> Iterable[User]:
        for ref in self._get_best_refs():
            try:
                metadata = State.load_metadata(ref.commit.tree)
                yield User.from_metadata(metadata)
            except Exception as e:
                l.debug(f"Unable to load user {e}")
                continue

    def state_ctx(self, user=None, version=None, locked=False):
        state = self.get_state(user=user, version=version)
        return StateContext(self, state, locked=locked)

    def get_tree(self, user):
        with self.commit_lock:
            options = [ref for ref in self.repo.refs if ref.name.endswith(f"{BINSYNC_BRANCH_PREFIX}/{user}")]
            if not options:
                raise ValueError(f'No such user "{user}" found in repository')

            # find the latest commit for the specified user!
            try:
                best = max(options, key=lambda ref: ref.commit.authored_date)
            except Exception as e:
                l.warning(f"Failed to get commit because: {e}")

            bct = best.commit.tree
        return bct

    def get_state(self, user=None, version=None):
        if user is None or user == self.master_user:
            # local state
            if self.state is None:
                try:
                    self.state = State.parse(
                        self.get_tree(user=self.master_user), version=version,
                        client=self,
                    )  # Also need to check if user is none here???
                except MetadataNotFoundError:
                    # we should return a new state
                    self.state = State(user if user is not None else self.master_user, client=self)
            return self.state
        else:
            try:
                state = State.parse(self.get_tree(user=user), version=version, client=self)
                return state
            except MetadataNotFoundError:
                return None

    def get_locked_state(self, user=None, version=None):
        with self.commit_lock:
            yield self.get_state(user=user, version=version)

    def start_updater_thread(self):
        if self._updater_thread is None:
            self._updater_thread = threading.Thread(target=self._updater_routine)
            self._updater_thread.start()
        else:
            raise Exception(
                "start_updater_thread() should not be called twice. There is already a worker thread running."
            )

    def _updater_routine(self):
        while True:
            time.sleep(self._commit_interval)
            self.update()

    def update(self):
        """
        Update both the local and remote repo knowledge of files through pushes/pulls and commits
        in the case of dirty files.
        """

        # do a pull if there is a remote repo connected
        if self.has_remote:
            self.pull()

        # attempt to commit dirty files in a update phase
        if self.get_state().dirty:
            self.commit_state()

        if self.has_remote:
            self.push()

        self._last_commit_ts = time.time()

    def commit_state(self, state=None, msg="Generic Change"):
        with self.commit_lock:
            self.checkout_to_master_user()
            if state is None:
                state = self.state

            if self.master_user != state.user:
                raise ExternalUserCommitError(f"User {self.master_user} is not allowed to commit to user {state.user}")

            assert self.master_user == state.user

            master_user_branch = next(o for o in self.repo.branches if o.name == self.user_branch_name)
            index = self.repo.index

            # dump the state
            state.dump(index)

            # commit changes
            self.repo.index.add([os.path.join(state.user, "*")])

            if not self.repo.index.diff("HEAD"):
                return

            # commit if there is any difference
            try:
                commit = index.commit(msg)
            except Exception as e:
                l.warning(f"Internal Git Commit Error: {e}")
                return

            master_user_branch.commit = commit
            state._dirty = False

            self.push()

    def sync_states(self, user=None):
        target_state = self.get_state(user)
        if target_state is None:
            print("Unable to find state for user", user)
            return

        my_state = self.get_state(self.master_user)

        my_state.copy_state(target_state)
        self.commit_state()

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

    def close(self):
        self.repo.close()
        del self.repo

    def _get_best_refs(self):
        candidates = {}
        for ref in self.repo.refs:  # type: git.Reference
            if f'{BINSYNC_BRANCH_PREFIX}/' not in ref.name:
                continue

            branch_name = ref.name.split("/")[-1]
            if branch_name in candidates:
                # if the candidate exists, and the new one is not remote, don't replace it
                if not ref.is_remote() or ref.remote_name != self.remote:
                    continue

            candidates[branch_name] = ref
        return candidates.values()

    def _setup_repo(self):
        with open(os.path.join(self.repo_root, ".gitignore"), "w") as f:
            f.write(".git/*\n")
        with open(os.path.join(self.repo_root, "binary_hash"), "w") as f:
            f.write(self.binary_hash)
        self.repo.index.add([".gitignore", "binary_hash"])
        self.repo.index.commit("Root commit")
        self.repo.create_head(BINSYNC_ROOT_BRANCH)

    def _get_stored_hash(self):
        branch = [ref for ref in self.repo.refs if ref.name.endswith(BINSYNC_ROOT_BRANCH)][0]
        return branch.commit.tree["binary_hash"].data_stream.read().decode().strip("\n")

    def list_files_in_tree(self, base_tree: git.Tree):
        """
        Lists all the files in a repo at a given tree

        :param commit: A gitpython Tree object
        """
        with self.commit_lock:
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

    def add_data(self, index: git.IndexFile, path: str, data: bytes):
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

    def remove_data(self, index: git.IndexFile, path: str):
        with self.commit_lock:
            fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
            pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
            index.remove([fullpath], working_tree=True)

