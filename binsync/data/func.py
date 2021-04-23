import os

import toml

from .base import Base
from ..utils import is_py2

long = int


class Function(Base):
    """
    :ivar int addr:     Address of the function.
    :ivar str name:     Name of the function.
    :ivar str notes:    Notes of the function.
    :ivar bool track:   To track or not
    """

    __slots__ = (
        "addr",
        "name",
        "notes",
        "track",
    )

    def __init__(self, addr, name=None, track=False, notes=None):
        self.addr = addr
        self.name = name
        self.notes = notes
        self.track = track

    def __getstate__(self):
        return {
            "addr": self.addr,
            "name": self.name,
            "notes": self.notes,
            "track": self.track,
        }

    def __setstate__(self, state):
        if not isinstance(state["addr"], (int, long)):
            raise TypeError("Unsupported type %s for addr." % type(state["addr"]))
        self.addr = state["addr"]
        self.name = state["name"]
        self.notes = state.get("notes", None)
        self.track = state["track"]

    def __eq__(self, other):
        return (
            isinstance(other, Function)
            and other.name == self.name
            and other.addr == self.addr
            and other.notes == self.notes
            and other.track == self.track
        )

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        func = Function(0)
        func.__setstate__(toml.loads(s))
        return func

    @classmethod
    def load_many(cls, path):

        with open(path, "r") as f:
            data = f.read()
        funcs_toml = toml.loads(data)

        for func_toml in funcs_toml.values():
            func = Function(0)
            try:
                func.__setstate__(func_toml)
            except TypeError:
                # Skip all unparsable entries
                continue
            yield func

    @classmethod
    def dump_many(cls, path, funcs):
        funcs = dict(("%x" % k, v.__getstate__()) for k, v in funcs.items())
        with open(path, "w") as f:
            toml.dump(funcs, f)
