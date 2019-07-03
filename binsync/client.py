
import os

import git

from .data import User
from .state import State
from .errors import MetadataNotFoundError


class Client:
    """
    The binsync Client.

    :ivar str master_user:  User name of the master user.
    :ivar str repo_root:    Local path of the Git repo.
    :ivar str remote:       Git remote.
    :ivar str branch:       Git branch.
    """
    def __init__(self, master_user, repo_root, remote="origin", branch="master"):
        self.master_user = master_user
        self.repo_root = repo_root
        self.remote = remote
        self.branch = branch

        try:
            # open the repo
            self.repo = git.Repo(self.repo_root)
        except git.InvalidGitRepositoryError:
            # initialization
            git.Repo.init(self.repo_root)
            self.repo = git.Repo(self.repo_root)

        assert not self.repo.bare  # it should not be a bare repo

        self.state = None  # TODO: Updating it

    def users(self):
        for d in os.listdir(self.repo_root):
            metadata_path = os.path.join(self.repo_root, d, "metadata.toml")
            if os.path.isfile(metadata_path):
                # Load metadata
                metadata = State.load_metadata(metadata_path)
                yield User.from_metadata(metadata)

    def base_path(self, user=None):
        if user is None:
            user = self.master_user
        return os.path.join(self.repo_root, user)

    def get_state(self, user=None, version=None):
        if user is None or user == self.master_user:
            # local state
            if self.state is None:
                try:
                    self.state = State.parse(self.base_path(user=user), version=version)
                except MetadataNotFoundError:
                    # we should return a new state
                    self.state = State(user if user is not None else self.master_user)
            return self.state
        else:
            try:
                state = State.parse(self.base_path(user=user), version=version)
                return state
            except MetadataNotFoundError:
                return None

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
        self.repo.index.commit("Save state")

    def close(self):
        self.repo.close()
        del self.repo
