import xmlrpc.client

from binsync.data import (
    Function, FunctionHeader
)


class BSBridgeClient:
    def __init__(self, host="localhost", port=6683):
        self.host = host
        self.port = port

        self.server = None

    #
    # Server Ops
    #

    @property
    def connected(self):
        return True if self.server else False

    def connect(self, host=None, port=None) -> bool:
        """
        Connects to the remote decompiler.
        """
        host = host or self.host
        port = port or self.port

        # create a server connection and test it
        try:
            self.server = xmlrpc.client.ServerProxy(f"http://{host}:{port}").bs
            self.server.ping()
        except (ConnectionRefusedError, AttributeError) as e:
            self.server = None
            return False

        return True

    def set_controller_status(self, status):
        self.server.alertUIConfigured(status)

    #
    # Public Facing API
    #

    #
    # Function Operations
    #

    def set_func_header(self, addr, fh: FunctionHeader):
        pass

    def set_func_name(self, addr, name):
        return self.server.setFunctionName(str(addr), name)

    def _set_func_type(self, addr, type_):
        pass

    def _set_func_arg(self, addr, offset, name, type_):
        pass