
import os

import toml

from .base import Base


class Function(Base):
    """
    :ivar int addr:     Address of the function.
    :ivar str name:     Name of the function.
    :ivar str comment:  Comment of the function.
    """
    def __init__(self, addr, name=None, comment=None):
        self.addr = addr
        self.name = name
        self.comment = comment

    def __getstate__(self):
        return {
            'addr': self.addr,
            'name': self.name,
            'comment': self.comment,
        }

    def __setstate__(self, state):
        self.addr = state["addr"]
        self.name = state["name"]
        self.comment = state["comment"]

    def __eq__(self, other):
        return (isinstance(other, Function) and
                other.name == self.name and
                other.addr == self.addr and
                other.comment == self.comment
                )

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        func = Function(0)
        func.__setstate__(toml.loads(s))

    @classmethod
    def load_many(cls, path):

        with open(path, "r") as f:
            data = f.read()
        funcs_toml = toml.loads(data)

        for func_toml in funcs_toml.values():
            func = Function(0)
            func.__setstate__(func_toml)
            yield func

    @classmethod
    def dump_many(cls, path, funcs):

        funcs = dict(("%x" % k, v.__getstate__()) for k, v in funcs.items())
        with open(path, "w") as f:
            toml.dump(funcs, f)
