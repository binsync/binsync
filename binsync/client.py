import time
import threading
import os
import subprocess
import re
import datetime
import logging

import git
import git.exc

from .data import User
from .state import State
from .errors import MetadataNotFoundError
from .utils import is_py3

_l = logging.getLogger(name=__name__)


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
        self.client.save_state(state=self.state)


class Client(object):
    """
    The binsync Client.

    :ivar str master_user:  User name of the master user.
    :ivar str repo_root:    Local path of the Git repo.
    :ivar str remote:       Git remote.
    :ivar str branch:       Git branch.
    :ivar int _commit_interval: The interval for committing local changes into the Git repo, pushing to the remote
                            side, and pulling from the remote.
    """

    def __init__(
        self,
        master_user,
        repo_root,
        remote="origin",
        branch="master",
        commit_interval=10,
        init_repo=False,
        remote_url=None,
        ssh_agent_pid=None,
        ssh_auth_sock=None,
    ):
        self.master_user = master_user
        self.repo_root = repo_root
        self.remote = remote
        self.branch = branch
        self.repo = None

        # ssh-agent info
        self.ssh_agent_pid = ssh_agent_pid  # type: int
        self.ssh_auth_sock = ssh_auth_sock  # type: str

        # three scenarios
        # 1. We already have the repo checked out
        # 2. We haven't checked out the repo, but there is a remote repo. In this case, we clone the repo from
        #    @remote_url
        # 3. There is no such repo, and we are the very first group of people trying to setup this repo. In this case,
        #    @init_repo should be True, and we will initialize the repo.

        try:
            # case 1
            # open the local repo
            self.repo = git.Repo(self.repo_root)
        except (git.NoSuchPathError, git.InvalidGitRepositoryError):
            # initialization
            assert not (init_repo is True and remote_url)
            if init_repo:
                # case 3
                self.repo = git.Repo.init(self.repo_root)
                self._add_git_ignore(self.repo_root)
            elif remote_url is not None:
                # case 2
                self.clone(remote_url)
            if not self.repo:
                self.repo = git.Repo(self.repo_root)

        assert not self.repo.bare  # it should not be a bare repo

        self._commit_interval = commit_interval
        self._worker_thread = None
        self._last_push_at = None  # type: datetime.datetime
        self._last_push_attempt_at = None  # type: datetime.datetime
        self._last_pull_at = None  # type: datetime.datetime
        self._last_pull_attempt_at = None  # type: datetime.datetime

        # timestamps
        self._last_commit_ts = 0

        self.state = None  # TODO: Updating it
        self.commit_lock = threading.Lock()

    @property
    def has_remote(self):
        """
        If there is a remote configured for our local repo.

        :return:    True if there is a remote, False otherwise.
        """
        return self.remote and any(r.name == self.remote for r in self.repo.remotes)

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

    def clone(self, remote_url):
        """
        Checkout from a remote_url to a local path specified by self.local_root.

        :param str remote_url:  The URL of the Git remote.
        :return:                None
        """

        env = self.ssh_agent_env()
        git.Repo.clone_from(remote_url, self.repo_root, env=env)

    def pull(self, print_error=False):
        """
        Pull changes from the remote side.

        :return:    None
        """

        self._last_pull_attempt_at = datetime.datetime.now()

        if self.has_remote:
            try:
                env = self.ssh_agent_env()
                with self.repo.git.custom_environment(**env):
                    self.repo.remotes[self.remote].pull()
                self._last_pull_at = datetime.datetime.now()
            except git.exc.GitCommandError as ex:
                if print_error:
                    print("Failed to pull from remote \"%s\".\n"
                          "Did you setup %s/master as the upstream of the local master branch?\n"
                          "\n"
                          "Git error: %s." % (
                              self.remote,
                              self.remote,
                              str(ex)
                          ))

    def push(self, print_error=False):
        """
        Push local changes to the remote side.

        :return:    None
        """

        self._last_push_attempt_at = datetime.datetime.now()

        if self.has_remote:
            try:
                env = self.ssh_agent_env()
                with self.repo.git.custom_environment(**env):
                    self.repo.remotes[self.remote].push()
                self._last_push_at = datetime.datetime.now()
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

    def users(self):
        for d in os.listdir(self.repo_root):
            metadata_path = os.path.join(self.repo_root, d, "metadata.toml")
            if os.path.isfile(metadata_path):
                # Load metadata
                metadata = State.load_metadata(metadata_path)
                yield User.from_metadata(metadata)

    def tally(self, users=None):
        """
        Return a dict of user names and what information they can provide, e.g.,
        {"user":
            {
                "functions": [0x400080],
            }
        }

        :param list users:  A list of user names or None if we don't want to limit the range of user names we care about.
        :return:            A dict with tally information.
        :rtype:             dict
        """

        if users is not None:
            users = set(users)
        else:
            users = [x.name for x in self.users()]

        all_info = {}

        for user in self.users():
            if user is None or user.name not in users:
                continue

            # what information does this user provide?
            info = {}
            state = self.get_state(user=user.name)
            info["function"] = list(state.functions.keys())
            info["comments"] = list(state.comments.keys())
            info["patches"] = list(
                {"obj_name": p.obj_name, "offset": p.offset}
                for p in state.patches.values()
            )

            all_info[user.name] = info

        return all_info

    def status(self):
        """
        Return a dict of status information.
        """

        d = {}

        d['remote_name'] = self.remote

        if self.repo is not None:
            d['last_commit_hash'] = self.repo.heads[0].commit.hexsha
            try:
                d['last_commit_time'] = self.repo.heads[0].commit.committed_datetime.replace(tzinfo=None)
            except IOError:  # sometimes GitPython throws this exception
                d['last_commit_time'] = "<unknown>"
            if any(r.name == self.remote for r in self.repo.remotes):
                d['remote_url'] = ";".join(self.repo.remotes[self.remote].urls)
            else:
                d['remote_url'] = "<does not exist>"

            d['last_push'] = self._last_push_at if self._last_push_at is not None else "never"
            d['last_push_attempt'] = self._last_push_attempt_at if self._last_push_attempt_at is not None else "never"
            d['last_pull'] = self._last_pull_at if self._last_pull_at is not None else "never"
            d['last_pull_attempt'] = self._last_pull_attempt_at if self._last_pull_attempt_at is not None else "never"

        return d

    def base_path(self, user=None):
        if user is None:
            user = self.master_user
        return os.path.join(self.repo_root, user)

    def state_ctx(self, user=None, version=None, locked=False):
        state = self.get_state(user=user, version=version)
        return StateContext(self, state, locked=locked)

    def get_state(self, user=None, version=None):
        if user is None or user == self.master_user:
            # local state
            if self.state is None:
                try:
                    self.state = State.parse(
                        self.base_path(user=user), version=version,
                        client=self,
                    )  # Also need to check if user is none here???
                except MetadataNotFoundError:
                    # we should return a new state
                    self.state = State(user if user is not None else self.master_user, client=self)
            return self.state
        else:
            try:
                state = State.parse(self.base_path(user=user), version=version, client=self)
                return state
            except MetadataNotFoundError:
                return None

    def get_locked_state(self, user=None, version=None):
        with self.commit_lock:
            yield self.get_state(user=user, version=version)

    def start_auto(self):
        if self._worker_thread is None:
            self._worker_thread = threading.Thread(target=self._worker_routine)
            self._worker_thread.start()
        else:
            raise Exception(
                "start_auto() should not be called twice. There is already a worker thread running."
            )

    def _worker_routine(self):
        while True:
            time.sleep(self._commit_interval)
            self.update()

    def update(self):
        """

        :return:
        """

        # do a pull... if there is a remote
        if self.has_remote:
            self.pull()

        print("IS DIRTY??", self.get_state().dirty)
        if self.get_state().dirty:
            # do a save!
            self.save_state()

        if self.has_remote:
            # do a push... if there is a remote
            self.push()

        self._last_commit_ts = time.time()

    def save_state(self, state=None):

        if state is None:
            state = self.state

        # you don't want to save as another user... unless you want to mess things up for your collaborators, in which
        # case, please comment out the following assertion.
        assert self.master_user == state.user

        path = self.base_path(user=state.user)

        if not os.path.exists(path):
            # create this folder if it does not exist
            os.mkdir(path)

        # dump the state
        state.dump(path)

        # commit changes
        self.repo.index.add([os.path.join(".", state.user, "*")])
        if self.repo.index.diff("HEAD"):
            # commit if there is any difference
            self.repo.index.commit("Save state")
            self.push()

    @staticmethod
    def discover_ssh_agent(ssh_agent_cmd):
        proc = subprocess.Popen(ssh_agent_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        if is_py3:
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
            return None, None
        ssh_agent_pid = int(m.group(1))

        m = re.search(r"Found ssh-agent socket at ([^\s]+)", stdout)
        if m is None:
            return None, None
        ssh_agent_sock = m.group(1)

        return ssh_agent_pid, ssh_agent_sock

    def close(self):
        self.repo.close()
        del self.repo

    def _add_git_ignore(self, repo_root):
        with open(os.path.join(repo_root, ".gitignore"), "w") as f:
            f.write(".git/*\n")
        self.repo.index.add([".gitignore"])
        self.repo.index.commit("Add .gitignore.")
