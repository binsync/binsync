try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

import os
from functools import wraps
from collections import defaultdict

from sortedcontainers import SortedDict
import toml

from .data import Function, Comment, Patch, StackVariable
from .errors import MetadataNotFoundError
from .utils import is_py2, is_py3

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
        self.stack_variables = defaultdict(dict)  # type: Dict[int,Dict[int,StackVariable]]
        self.patches = SortedDict()

    @property
    def dirty(self):
        return self._dirty

    def ensure_dir_exists(self, dir_name):
        if not os.path.exists(dir_name):
            os.mkdir(dir_name)
        if not os.path.isdir(dir_name):
            raise RuntimeError("Cannot create directory %s. Maybe it conflicts with an existing file?" % dir_name)

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

        # dump stack variables, one file per function
        stack_var_base = os.path.join(base_path, "stack_vars")
        self.ensure_dir_exists(stack_var_base)
        for func_addr, stack_vars in self.stack_variables.items():
            path = os.path.join(stack_var_base, "%08x.toml" % func_addr)
            StackVariable.dump_many(path, stack_vars)

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

        # load stack variables
        stack_var_base = os.path.join(base_path, "stack_vars")
        if os.path.isdir(stack_var_base):
            for f in os.listdir(stack_var_base):
                svs = list(StackVariable.load_many(os.path.join(stack_var_base, f)))
                d = dict((v.stack_offset, v) for v in svs)
                if svs:
                    s.stack_variables[svs[0].func_addr] = d

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

    @dirty_checker
    def set_stack_variable(self, func_addr, offset, variable):
        if func_addr in self.stack_variables \
                and offset in self.stack_variables[func_addr] \
                and self.stack_variables[func_addr][offset] == variable:
            # no update is required
            return False

        self.stack_variables[func_addr][offset] = variable
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

        cmt = self.comments[addr]
        if is_py2() and isinstance(cmt, unicode):
            cmt = str(cmt)
        return cmt

    def get_comments(self, start_addr, end_addr=None):
        for k in self.comments.irange(start_addr, reverse=False):
            if k >= end_addr:
                break
            cmt = self.comments[k]
            if is_py2() and isinstance(cmt, unicode):
                cmt = str(cmt)
            yield cmt

    def get_patch(self, addr):

        if addr not in self.patches:
            raise KeyError("There is no patch at address %#x." % addr)

        return self.patches[addr]

    def get_patches(self):
        return self.patches.values()

    def get_stack_variable(self, func_addr, offset):
        if func_addr not in self.stack_variables:
            raise KeyError("No stack variables are defined for function %#x." % func_addr)
        if offset not in self.stack_variables[func_addr]:
            raise KeyError("No stack variable exists at offset %d in function %#x." % (offset, func_addr))
        return self.stack_variables[func_addr][offset]

    def get_stack_variables(self, func_addr):
        if func_addr not in self.stack_variables:
            raise KeyError("No stack variables are defined for function %#x." % func_addr)
        return self.stack_variables[func_addr].items()
