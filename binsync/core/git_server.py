import rpyc
from rpyc.utils.server import ThreadedServer

from binsync.core.git_actions_util import atomic_git_action


class GitServer(rpyc.Service):
    def __init__(self, mode="object"):
        self.repo = None  # Initialize your Git repository here
        self.mode = mode  # Store the mode (object or server)

    def on_connect(self, conn: rpyc.Connection):
        pass

    def on_disconnect(self, conn: rpyc.Connection):
        pass

    # Define remote Git operations with the atomic_git_action decorator
    @atomic_git_action
    def clone(self, remote_url: str, local_path: str):
        # You can access self.mode here to check the mode
        pass

    @atomic_git_action
    def commit(self, local_path: str, commit_msg: str):
        # You can access self.mode here to check the mode
        pass

    @atomic_git_action
    def pull(self, local_path: str):
        # You can access self.mode here to check the mode
        pass

    @atomic_git_action
    def push(self, local_path: str):
        # You can access self.mode here to check the mode
        pass


# if __name__ == "__main__":
#     # Create an instance of the GitServer with the desired mode (object or server)
#     server = ThreadedServer(GitServer(mode="object"), port=18861)
#     server.start()
