import xmlrpc.client
from functools import wraps

import json

from binsync.data import (
    Function, FunctionHeader
)


def stringify_args(f):
    @wraps(f)
    def _stringify_args(self, *args, **kwargs):
        new_args = list()
        for arg in args:
            if isinstance(arg, int):
                new_arg = hex(arg)
            elif isinstance(arg, dict):
                new_arg = json.loads(json.dumps(arg), parse_int=lambda o: hex(o))
            else:
                new_arg = arg

            new_args.append(new_arg)

        return f(self, *new_args, **kwargs)

    return _stringify_args

class BSGhidraClient:
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

    def alert_ui_configured(self, status):
        self.server.alertUIConfigured(status)

    #
    # Public Facing API
    #

    @property
    def base_addr(self):
        val = self.server.baseAddr()
        if not val:
            return None

        return int(val, 16)

    @property
    def binary_hash(self):
        return self.server.binaryHash()

    @property
    def binary_path(self):
        return self.server.binaryPath()

    def goto_address(self, addr):
        return self.server.gotoAddress(addr)

    #
    # Function Operations
    #

    @stringify_args
    def set_func_name(self, addr, name):
        return self.server.setFunctionName(addr, name)

    @stringify_args
    def set_func_rettype(self, addr, type_str):
        return self.server.setFunctionRetType(addr, type_str)

    @stringify_args
    def set_stack_var_name(self, addr, offset, name):
        return self.server.setStackVarName(addr, offset, name)

    @stringify_args
    def set_stack_var_type(self, addr, offset, type_):
        return self.server.setStackVarType(addr, offset, type_)

