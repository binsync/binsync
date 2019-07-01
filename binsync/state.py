
import os
from functools import wraps

import toml

from .data import Function
from .errors import MetadataNotFoundError


def dirty_checker(f):
    @wraps(f)
    def dirtycheck(self, *args, **kwargs):
        r = f(self, *args, **kwargs)
        if r is True:
            self._dirty = True
        return r
    return dirtycheck


class State:
    """
    The state.

    :ivar str user:     Name of the user.
    :ivar int version:  Version of the state, starting from 0.
    """
    def __init__(self, user, version=None):
        self.user = user
        self.version = version if version is not None else 0

        # dirty bit
        self._dirty = True

        # data
        self.functions = { }

    def save_metadata(self, path):
        d = {
            'user': self.user,
            'version': self.version,
        }
        with open(path, "w") as f:
            toml.dump(d, f)

    def dump(self, base_path):
        # dump metadata
        self.save_metadata(os.path.join(base_path, "metadata.toml"))

        # dump function
        Function.dump_many(os.path.join(base_path, "functions.toml"), self.functions)

    @staticmethod
    def load_metadata(path):
        with open(path, "r") as f:
            data = f.read()
        metadata = toml.loads(data)
        return metadata

    @classmethod
    def parse(cls, base_path, version=None):
        s = State(None)

        # load metadata
        try:
            metadata = cls.load_metadata(os.path.join(base_path, "metadata.toml"))
        except FileNotFoundError:
            # metadata is not found
            raise MetadataNotFoundError()
        s.user = metadata['user']

        s.version = version if version is not None else metadata['version']

        # load function
        functions = { }
        for func in Function.load_many(os.path.join(base_path, "functions.toml")):
            functions[func.addr] = func
        s.functions = functions

        # clear the dirty bit
        s._dirty = False

        return s

    #
    # Pushers
    #

    @dirty_checker
    def set_function(self, func):

        if not isinstance(func, Function):
            raise TypeError("Unsupported type %s. Expecting type %s." % (type(func), Function))

        if func.addr in self.functions and self.functions[func.addr] == func:
            # no update is required
            return False

        self.functions[func.addr] = func
        return True

    #
    # Pullers
    #

    def get_function(self, addr):

        if addr not in self.functions:
            raise KeyError("Function %x is not found in the db." % addr)

        return self.functions[addr]
