import git
import os
import threading
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

# Mb make a request handler?
class GitServer:
    def __init__(self, repo_path, host, port):
        self.repo_path = repo_path
        self.host = host
        self.port = port
        self.repo = git.Repo(repo_path)
        self.lock = threading.Lock()
        self.server = SimpleXMLRPCServer((host, port),
                                         requestHandler=SimpleXMLRPCRequestHandler,
                                         logRequests=True)
        self.register_functions()

    def register_functions(self):
        self.server.register_function(self.commit_state, "commit_state")
        self.server.register_function(self.get_state, "get_state")
        self.server.register_function(self.push, "pushsuttf")
        self.server.register_function(self.pull, "pull")

    def commit_state(self, user, state):
        pass