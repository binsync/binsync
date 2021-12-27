import os
import time

import toml
import typing

from collections import defaultdict

from .artifact import Artifact
from .stack_variable import StackVariable


#
# Function Header Classes
#

class FunctionArgument(Artifact):
    __slots__ = (
        "last_change",
        "idx",
        "name",
        "type_str",
        "size"
    )

    def __init__(self, idx, name, type_str, size, last_change=None):
        super(FunctionArgument, self).__init__(last_change=last_change)
        self.idx = idx
        self.name = name
        self.type_str = type_str
        self.size = size

    @classmethod
    def parse(cls, s):
        fa = FunctionArgument(None, None, None, None)
        fa.__setstate__(toml.loads(s))
        return fa


class FunctionHeader(Artifact):
    __slots__ = (
        "last_change",
        "name",
        "addr",
        "comment",
        "ret_type",
        "args"
    )

    def __init__(self, name, addr, comment=None, ret_type=None, args=None, last_change=None):
        super(FunctionHeader, self).__init__(last_change=last_change)
        self.name = name
        self.addr = addr
        self.comment = comment
        self.ret_type = ret_type
        self.args = args or {}

    def __getstate__(self):
        return {
            "last_change": self.last_change,
            "name": self.name,
            "addr": self.addr,
            "comment": self.comment,
            "ret_type_str": self.ret_type,
            "args": {
                str(idx): arg.__getstate__() for idx, arg in self.args.items()
            }
        }

    @classmethod
    def parse(cls, s):
        loaded_s = toml.loads(s)
        if len(loaded_s) <= 0:
            return None

        fh = FunctionHeader(None, None)
        fh.__setstate__(toml.loads(s))
        return fh


#
# Full Function Class
#

class Function(Artifact):
    """
    The Function class describes a Function found a decompiler. There are three components to a function:
    1. Metadata
    2. Header
    3. Stack Vars

    The metadata contains info on changes and size. The header holds the function comment, return type,
    and arguments (including their types). The stack vars contain StackVariables.
    """

    __slots__ = (
        "last_change",
        "addr",
        "header",
        "stack_vars"
    )

    def __init__(self, addr, header=None, stack_vars=None, last_change=None):
        super(Function, self).__init__(last_change=last_change)

        self.addr = addr
        self.header = header
        self.stack_vars: typing.Dict[int, StackVariable] = stack_vars or {}

    def __getstate__(self):
        return {
            "metadata": {
                "addr": self.addr,
                "last_change": self.last_change
            },

            "header": self.header.__getstate__() if self.header else None,

            "stack_vars": {
                "%x" % offset: stack_var.__getstate__() for offset, stack_var in self.stack_vars.items()
            }
        }

    def __setstate__(self, state):
        if not isinstance(state["metadata"]["addr"], int):
            raise TypeError("Unsupported type %s for addr." % type(state["metadata"]["addr"]))

        metadata, header, stack_vars = state["metadata"], state.get("header", None), state["stack_vars"]

        self.addr = metadata["addr"]
        self.last_change = metadata.get("last_change", None)

        self.header = FunctionHeader.parse(toml.dumps(header))

        self.stack_vars = {
            int(off, 16): StackVariable.parse(toml.dumps(stack_var)) for off, stack_var in stack_vars.items()
        }

    @property
    def name(self):
        return self.header.name if self.header else None

    def set_stack_var(self, name, off: int, off_type: int, size: int, type_str, last_change):
        self.stack_vars[off] = StackVariable(off, off_type, name, type_str, size, self.addr, last_change=last_change)

    @classmethod
    def parse(cls, s):
        func = Function(None)
        func.__setstate__(s)
        return func

    @classmethod
    def load(cls, func_toml):
        f = Function(None)
        f.__setstate__(func_toml)
        return f
