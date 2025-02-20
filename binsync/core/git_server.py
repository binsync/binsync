import os
import threading
import git
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

# Restrict to a particular path. Took from the python docs.
# https://docs.python.org/3/library/xmlrpc.server.html#xmlrpc.server.SimpleXMLRPCRequestHandler
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class GitServer:
    def __init__(self, repo_path, mode="object", host="localhost", port=5000):
        """
        Initialize the GitServer.

        :param repo_path: Path to the local Git repository.
        :param mode: 'object' for in-process operation or 'server' to run an XMLRPC server.
        :param host: Host for XMLRPC server (used only in server mode).
        :param port: Port for XMLRPC server (used only in server mode).
        """
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

    def register_functions(self):
        """
        Register Git operations for XMLRPC.
        """
        self.server.register_function(self.commit_state, "commit_state")
        self.server.register_function(self.push, "push")
        self.server.register_function(self.pull, "pull")

    def serve_forever(self):
        """
        If running in server mode, start the XMLRPC server loop.
        """
        if self.mode != "server":
            # No... How'd we get here lmao
            raise RuntimeError("GitServer is not in server mode.")
        print(f"GitServer running on {self.server.server_address} in server mode...")
        self.server.serve_forever()

    def commit_state(self, state, msg, priority=None, no_checkout=False):
        """
        Commit the provided state to the Git repo.

        :param state: A state object (or its serialized form) which must support a `dump(index)` method.
        :param msg: Commit message.
        :param priority: (Optional) Priority value for the commit (not used here).
        :param no_checkout: If False, ensure the repo is on the proper branch before committing.
        :return: A status message.
        """
        with self.lock:
            # Prob wanna check and change branches here, too lazy for that rn
            if not no_checkout:
                self._checkout_to_master_user()

            # Prepare the index by dumping the state.
            index = self.repo.index
            try:
                state.dump(index)
            except Exception as e:
                return {"status": "error", "message": f"State dump failed: {e}"}

            # Stage any additional changes.
            user_dir = os.path.join(self.repo_path, state.user)
            index.add([os.path.join(user_dir, "*")])
            self.repo.git.add(update=True) # TODO: Copy over the behavior of the client over here, too lazy rn

            # Check if there are changes to commit.
            if not self.repo.index.diff("HEAD"):
                return {"status": "noop", "message": "No changes to commit"}

            # Commit the changes.
            try:
                commit = index.commit(msg)
                return {"status": "success", "commit": commit.hexsha}
            except Exception as e:
                return {"status": "error", "message": f"Commit failed: {e}"}

    def push(self, remote="origin", branch="main", print_error=False, priority=None):
        """
        Push local changes to the remote repository.
        :param remote: Remote name.
        :param branch: Branch name.
        :param print_error: (Optional) Whether to print errors.
        :param priority: (Optional) Priority (not used).
        :return: A status message.
        """
        with self.lock:
            try:
                self.repo.remotes[remote].push(branch) # TODO: Copy over the behavior of the client over here, too lazy rn
                return {"status": "success", "message": f"Pushed to {remote}/{branch}"}
            except Exception as e:
                err_msg = f"Push failed: {e}"
                if print_error:
                    print(err_msg)
                return {"status": "error", "message": err_msg}

    def pull(self, remote="origin", branch="main", priority=None):
        """
        Pull changes from the remote repository.
        :param remote: Remote name.
        :param branch: Branch name.
        :param priority: (Optional) Priority (not used).
        :return: A status message.
        """
        with self.lock:
            try:
                # Checkout to a stable branch before pulling.
                self.repo.git.checkout(branch)
                self.repo.git.pull(remote, branch) # TODO: Copy over the behavior of the client over here, too lazy rn
                return {"status": "success", "message": f"Pulled from {remote}/{branch}"}
            except Exception as e:
                return {"status": "error", "message": f"Pull failed: {e}"}

    def _checkout_to_master_user(self):
        """
        Ensure the repository is checked out to the master user's branch.
        In your full implementation, this would switch branches if needed.
        """
        master_branch = "master"  # TODO: Replace with self.user_branch_name if available.
        try:
            self.repo.git.checkout(master_branch)
            # TODO: Copy over the behavior of the client over here, too lazy rn
        except Exception as e:
            raise RuntimeError(f"Failed to checkout to {master_branch}: {e}")