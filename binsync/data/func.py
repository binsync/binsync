import os
import time

import toml

from .base import Base
from ..utils import is_py2

long = int


class Function(Base):
    """
    :ivar int addr:         Address of the function.
    :ivar str name:         Name of the function.
    :ivar int last_change:  Unix time of the last change.
    :ivar str notes:        Notes of the function.
    """

    __slots__ = (
        "addr",
        "name",
        "notes",
        "last_change",
    )

    def __init__(self, addr, name=None, notes=None, last_change=-1):
        self.addr = addr
        self.name = name
        self.notes = notes
        self.last_change = last_change

    def __getstate__(self):
        return {
            "addr": self.addr,
            "name": self.name,
            "notes": self.notes,
            "last_change": self.last_change,
        }

    def __setstate__(self, state):
        if not isinstance(state["addr"], (int, long)):
            raise TypeError("Unsupported type %s for addr." % type(state["addr"]))
        self.addr = state["addr"]
        self.name = state.get("name", None)
        self.notes = state.get("notes", None)
        self.last_change = state["last_change"]

    def __eq__(self, other):
        if isinstance(other, Function):
            return other.name == self.name \
                   and other.addr == self.addr \
                   and other.notes == self.notes
        return False

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        func = Function(0)
        func.__setstate__(toml.loads(s))
        return func

    @classmethod
    def load_many(cls, funcs_toml):
        for func_toml in funcs_toml.values():
            func = Function(0)
            try:
                func.__setstate__(func_toml)
            except TypeError:
                # Skip all unparsable entries
                continue
            yield func

    @classmethod
    def dump_many(cls, funcs):
        return dict(("%x" % k, v.__getstate__()) for k, v in funcs.items())
