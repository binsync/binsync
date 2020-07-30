try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

import os
from functools import wraps
from collections import defaultdict

from sortedcontainers import SortedDict
import toml

from .data import Function, Comment, Patch
from .errors import MetadataNotFoundError
from .utils import is_py3

if is_py3():
    from typing import Dict


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
        self.user = user  # type: str
        self.version = version if version is not None else 0  # type: int

        # dirty bit
        self._dirty = True  # type: bool

        # data
        self.functions = {}  # type: Dict[int,Function]
        self.comments = SortedDict()  # type: Dict[int,str]
        self.stack_variables = defaultdict(dict)
        self.patches = SortedDict()

    @property
    def dirty(self):
        return self._dirty

    def save_metadata(self, path):
        d = {
            "user": self.user,
            "version": self.version,
        }
        with open(path, "w") as f:
            toml.dump(d, f)

    def dump(self, base_path):
        # dump metadata
        self.save_metadata(os.path.join(base_path, "metadata.toml"))

        # dump function
        Function.dump_many(os.path.join(base_path, "functions.toml"), self.functions)

        # dump comments
        Comment.dump_many(os.path.join(base_path, "comments.toml"), self.comments)

        # dump patches
        Patch.dump_many(os.path.join(base_path, "patches.toml"), self.patches)

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
        s.user = metadata["user"]

        s.version = version if version is not None else metadata["version"]

        # load function
        funcs_toml_path = os.path.join(base_path, "functions.toml")
        if os.path.isfile(funcs_toml_path):
            functions = {}
            for func in Function.load_many(funcs_toml_path):
                functions[func.addr] = func
            s.functions = functions

        # load comments
        comments_toml_path = os.path.join(base_path, "comments.toml")
        if os.path.isfile(comments_toml_path):
            comments = {}
            for comm in Comment.load_many(comments_toml_path):
                comments[comm.addr] = comm.comment
            s.comments = SortedDict(comments)

        # load patches
        patches_toml_path = os.path.join(base_path, "patches.toml")
        if os.path.isfile(patches_toml_path):
            patches = {}
            for patch in Patch.load_many(patches_toml_path):
                patches[patch.offset] = patch
            s.patches = SortedDict(patches)

        # clear the dirty bit
        s._dirty = False

        return s

    #
    # Pushers
    #

    @dirty_checker
    def set_function(self, func):

        if not isinstance(func, Function):
            raise TypeError(
                "Unsupported type %s. Expecting type %s." % (type(func), Function)
            )

        if func.addr in self.functions and self.functions[func.addr] == func:
            # no update is required
            return False

        self.functions[func.addr] = func
        return True

    @dirty_checker
    def set_comment(self, addr, comment):

        if addr in self.comments and self.comments[addr] == comment:
            # no update is required
            return False

        self.comments[addr] = comment
        return True

    @dirty_checker
    def set_patch(self, addr, patch):

        if addr in self.patches and self.patches[addr] == patch:
            # no update is required
            return False

        self.patches[addr] = patch
        return True

    #
    # Pullers
    #

    def get_function(self, addr):

        if addr not in self.functions:
            raise KeyError("Function %x is not found in the db." % addr)

        return self.functions[addr]

    def get_comment(self, addr):

        if addr not in self.comments:
            raise KeyError("There is no comment at address %#x." % addr)

        return self.comments[addr]

    def get_comments(self, start_addr, end_addr=None):
        for k in self.comments.irange(start_addr, reverse=False):
            if k >= end_addr:
                break
            yield self.comments[k]

    def get_patch(self, addr):

        if addr not in self.patches:
            raise KeyError("There is no patch at address %#x." % addr)

        return self.patches[addr]

    def get_patches(self):
        return self.patches.values()
