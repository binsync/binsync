import xmlrpc.client
from functools import wraps

import json
from typing import Optional

from binsync.data import (
    Function, FunctionHeader
)


def stringify_args(f):
    @wraps(f)
    def _stringify_args(self, *args, **kwargs):
        new_args = list()
        for arg in args:
            if isinstance(arg, int) and not isinstance(arg, bool):
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

    def context(self):
        if not self.server:
            return Function(0, 0, header=FunctionHeader("", 0))

        out = self.server.context()
        name = out["name"] or ""
        try:
            addr = int(out["addr"], 16)
        except:
            addr = 0

        return Function(addr, 0, header=FunctionHeader(name, addr))

    @property
    def base_addr(self) -> Optional[int]:
        val = self.server.baseAddr()
        if not val:
            return None

        return int(val, 16)

    @property
    def binary_hash(self) -> str:
        return self.server.binaryHash()

    @property
    def binary_path(self) -> Optional[str]:
        return self.server.binaryPath()

    @stringify_args
    def goto_address(self, addr) -> bool:
        return self.server.gotoAddress(addr)

    @stringify_args
    def decomiple(self, addr) -> str:
        return self.server.decompile(addr)

    #
    # Function Operations
    #

    @stringify_args
    def set_func_name(self, addr: int, name: str) -> bool:
        return self.server.setFunctionName(addr, name)

    @stringify_args
    def set_func_rettype(self, addr: int, type_str: str) -> bool:
        return self.server.setFunctionRetType(addr, type_str)

    @stringify_args
    def set_stack_var_name(self, addr: int, offset: int, name: str) -> bool:
        return self.server.setStackVarName(addr, offset, name)

    @stringify_args
    def set_stack_var_type(self, addr: int, offset: int, type_: str) -> bool:
        return self.server.setStackVarType(addr, offset, type_)

    @stringify_args
    def get_function(self, addr: int) -> dict:
        return self.server.getFunction(addr)

    @stringify_args
    def get_functions(self) -> dict:
        return self.server.getFunctions()

    @stringify_args
    def get_stack_vars(self, addr: int) -> dict:
        return self.server.getStackVars(addr)

    #
    # Global Operations
    #
    
    @stringify_args
    def set_global_var_name(self, addr: int, name: str) -> bool:
        return self.server.setGlobalVarName(addr, name)

    @stringify_args
    def get_global_var(self, addr: int) -> dict:
        return self.server.getGlobalVariable(addr)

    @stringify_args
    def get_global_vars(self) -> dict:
        return self.server.getGlobalVariables()

    #
    # Comment Ops
    #

    @stringify_args
    def set_comment(self, addr: int, comment: str, is_decompiled: bool) -> bool:
        return self.server.setComment(addr, comment, is_decompiled)
