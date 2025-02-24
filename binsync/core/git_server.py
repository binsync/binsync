import datetime
import os
import threading
import re
import git
import logging
from typing import Iterable, Optional
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

from binsync.core import MetadataNotFoundError
from binsync.core.scheduler import SchedSpeed
from binsync.core.state import State, toml_file_to_dict
from binsync.core.user import User


l = logging.getLogger(__name__)
BINSYNC_BRANCH_PREFIX = 'binsync'
BINSYNC_ROOT_BRANCH = f'{BINSYNC_BRANCH_PREFIX}/__root__'

logging.getLogger("git").setLevel(logging.ERROR)


# Restrict to a particular path. Took from the python docs.
# https://docs.python.org/3/library/xmlrpc.server.html#xmlrpc.server.SimpleXMLRPCRequestHandler
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)


class GitServer:
    DEFAULT_COMMIT_MSG = "Generic BS Server Commit"

    def __init__(self, repo_path, mode="object", host="localhost", port=5000):
        """
        Initialize the GitServer.

        :param repo_path: Path to the local Git repository.
        :param mode: 'object' for in-process operation or 'server' to run an XMLRPC server.
        :param host: Host for XMLRPC server (used only in server mode).
        :param port: Port for XMLRPC server (used only in server mode).
        """
        self.active_remote = None
        self.ssh_auth_sock = None  # type: Optional[int]
        self.ssh_agent_pid = None  # type: Optional[int]
        # Fields taken from client ^
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)
        # Lock for thread safety. I might copy over the atomic git action decorator in here if needed.
        self.lock = threading.Lock()
        self.mode = mode

        # If we're in server mode, start the XMLRPC server.
        # In object mode, we'll just use the GitServer object directly, with basically duplicated client code.
        if self.mode == "server":
            self.server = SimpleXMLRPCServer((host, port),
                                             requestHandler=RequestHandler,
                                             allow_none=True,
                                             logRequests=True)
            self.register_functions()

    # @property
    # def user_branch_name(self):
    #     return f"{BINSYNC_BRANCH_PREFIX}/{self.master_user}"

    def register_functions(self):
        """
        Register Git operations for XMLRPC.
        """
        self.server.register_function(self.commit_state, "commit_state")
        self.server.register_function(self.push, "push")
        self.server.register_function(self.pull, "pull")
        self.server.register_function(self.get_state, "get_state")
        self.server.register_function(self.parse_state_from_commit, "parse_state_from_commit")

    def serve_forever(self):
        """
        If running in server mode, start the XMLRPC server loop.
        """
        if self.mode != "server":
            # No... How'd we get here lmao
            raise RuntimeError("GitServer is not in server mode.")
        print(f"GitServer running on {self.server.server_address} in server mode...")
        self.server.serve_forever()

    @staticmethod
    def parse_state_from_commit(repo: git.Repo, user=None, commit_hash=None, is_master=False, client=None) -> State:
        if user is None and commit_hash is None:
            raise ValueError("Must specify either a user or a commit hash")

        state = State(None)
        try:
            state = State.parse(
                GitServer._get_tree(user, repo, commit_hash=commit_hash),
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


    def get_state(self, user=None, priority=None, no_cache=False, commit_hash=None, master_user=None) -> State:
        # Pass for now until we figure out how to handle the cache in the server
        pass
        
        if user is None:
            user = master_user

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
    def has_remote(self, target_remote):
        """
        If there is a remote configured for our local repo.

        :return:    True if there is a remote, False otherwise.
        """
        return target_remote and any(r.name == target_remote for r in self.repo.remotes)

    def commit_state(self, state, msg, priority=None, no_checkout=False, master_user=None):
        """
        Commit the provided state to the Git repo.

        :param state: A state object (or its serialized form) which must support a `dump(index)` method.
        :param msg: Commit message.
        :param priority: (Optional) Priority value for the commit (not used here).
        :param no_checkout: If False, ensure the repo is on the proper branch before committing.
        :param master_user: The user who is committing the state.
        :return: A status message.
        """
        # TODO: Ask Zion if locks are sufficient or if we need to copy over the atomic git action decorator
        with self.lock:
            msg = msg or self.DEFAULT_COMMIT_MSG
            if master_user != state.user:
                from binsync.core import ExternalUserCommitError
                raise ExternalUserCommitError(f"User {master_user} is not allowed to commit to user {state.user}")
            if not no_checkout:
                self._checkout_to_master_user(master_user)

            master_user_branch = next(o for o in self.repo.branches if o.name == master_user)
            index = self.repo.index

            # dump the state
            state.dump(index)

            # commit changes
            # Also this is just copy-pasted from the client, it should be committing for the passed user.
            self.repo.index.add([os.path.join(state.user, "*")])
            self.repo.git.add(update=True)

            if not self.repo.index.diff("HEAD"):
                return

            # commit if there is any difference
            try:
                commit = index.commit(msg)
            except Exception as e:
                l.warning(f"Internal Git Commit Error: {e}")
                return
            last_commit_time = datetime.datetime.now(tz=datetime.timezone.utc)
            master_user_branch.commit = commit
            state._dirty = False
            # TODO: Normal client doesn't return the last commit time, but it might want to know,
            return last_commit_time

    def pull(self, remote="origin", branch="main", priority=None):
        """
        Pull changes from the remote repository.
        :param remote: Remote name.
        :param branch: Branch name.
        :param priority: (Optional) Priority (not used).
        :return: A status message.
        """
        with self.lock:
            # The server isn't doing something with this yet, but client wants it, mb return it
            last_pull_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
            try:
                env = self.ssh_agent_env()
            except Exception:
                return

            with self.repo.git.custom_environment(**env):
                # dangerous remote operations happen here
                try:
                    self._localize_remote_branches()
                    self.repo.git.checkout(BINSYNC_ROOT_BRANCH)
                    self.repo.git.pull("--all")
                    # Server prob doesn't care about last pull time.
                    # _last_pull_time = datetime.datetime.now(tz=datetime.timezone.utc)
                    self.active_remote = True
                except Exception as e:
                    #l.debug(f"Pull exception {e}")
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

            # TODO: Figure out how we want to handle the cache in the server
            # self._update_cache()

    def push(self, remote="origin", print_error=False, priority=None, master_user=None):
        """
        Push local changes to the remote repository.
        :param remote: Remote name.
        :param print_error: (Optional) Whether to print errors.
        :param priority: (Optional) Priority (not used).
        :param master_user: The user who is pushing the changes.
        :return: A status message.
        """
        with self.lock:
            # The server isn't doing something with this yet, but client wants it, mb return it
            last_push_attempt_time = datetime.datetime.now(tz=datetime.timezone.utc)
            self._checkout_to_master_user(master_user)
            try:
                env = self.ssh_agent_env()
                with self.repo.git.custom_environment(**env):
                    self.repo.remotes[remote].push(BINSYNC_ROOT_BRANCH)
                    self.repo.remotes[remote].push(master_user)  # On client side this is user_branch_name
                _last_push_time = datetime.datetime.now(tz=datetime.timezone.utc)
                # l.debug("Push completed successfully at %s", self._last_push_ts)
                # TODO: Figure out how to emulate to active remote behavior in server if we have two clients, for now I'm setting this in init
                self.active_remote = True
            except git.exc.GitCommandError as ex:
                self.active_remote = False
                l.debug(f"Failed to push b/c {ex}")


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
                print("INDEX ERROR")
                continue

            # never try to track things already tracked
            if local_name in local_branches:
                continue

            try:
                self.repo.git.checkout('--track', branch.name)
            except git.GitCommandError as e:
                continue

    def _checkout_to_master_user(self, user_branch_name):
        """
        Ensure the repository is checked out to the master user's branch.
        In your full implementation, this would switch branches if needed.
        """
        try:
            self.repo.git.checkout(user_branch_name)
        except Exception as e:
            raise RuntimeError(f"Failed to checkout to {user_branch_name}: {e}")

    def ssh_agent_env(self):
        if self.ssh_agent_pid is not None and self.ssh_auth_sock is not None:
            env = {
                'SSH_AGENT_PID': str(self.ssh_agent_pid),
                'SSH_AUTH_SOCK': str(self.ssh_auth_sock),
            }
        else:
            env = {}
        return env

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
