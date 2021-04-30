try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

import os
from functools import wraps
from collections import defaultdict
import pathlib

from sortedcontainers import SortedDict
import toml
import git

from .data import Function, Comment, Patch, StackVariable
from .errors import MetadataNotFoundError
from .utils import is_py2, is_py3

if is_py3():
    from typing import Dict, TYPE_CHECKING, Optional
    if TYPE_CHECKING:
        from .client import Client


def dirty_checker(f):
    @wraps(f)
    def dirtycheck(self, *args, **kwargs):
        r = f(self, *args, **kwargs)
        if r is True:
            self._dirty = True
        return r

    return dirtycheck


def add_data(index: git.IndexFile, path: str, data: bytes):
    fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
    pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
    with open(fullpath, 'wb') as fp:
        fp.write(data)
    index.add([fullpath])


class State:
    """
    The state.

    :ivar str user:     Name of the user.
    :ivar int version:  Version of the state, starting from 0.
    """

    def __init__(self, user, version=None, client=None):
        # metadata info
        self.user = user  # type: str
        self.version = version if version is not None else 0  # type: int
        self.last_push_func = -1
        self.last_push_time = -1

        # the client
        self.client = client  # type: Optional[Client]

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

    def dump_metadata(self, index, last_push_time: int, last_push_func: int):
        d = {
            "user": self.user,
            "version": self.version,
            "last_push_func": last_push_func,
            "last_push_time": last_push_time
        }
        add_data(index, 'metadata.toml', toml.dumps(d).encode())

    def dump(self, index: git.IndexFile, last_push_func: int, last_push_time: int):
        # dump metadata
        self.dump_metadata(index, last_push_time, last_push_func)

        # dump function
        add_data(index, 'functions.toml', toml.dumps(Function.dump_many(self.functions)).encode())

        # dump comments
        add_data(index, 'comments.toml', toml.dumps(Comment.dump_many(self.comments)).encode())

        # dump patches
        add_data(index, 'patches.toml', toml.dumps(Patch.dump_many(self.patches)).encode())

        # dump stack variables, one file per function
        for func_addr, stack_vars in self.stack_variables.items():
            path = os.path.join('stack_vars', "%08x.toml" % func_addr)
            add_data(index, path, toml.dumps(StackVariable.dump_many(stack_vars)).encode())

    @staticmethod
    def load_metadata(tree):
        return toml.loads(tree['metadata.toml'].data_stream.read().decode())

    @classmethod
    def parse(cls, tree, version=None, client=None):
        s = cls(None, client=client)

        # load metadata
        try:
            metadata = cls.load_metadata(tree)
        except:
            # metadata is not found
            raise MetadataNotFoundError()
        s.user = metadata["user"]

        s.version = version if version is not None else metadata["version"]

        # load function
        try:
            funcs_toml = toml.loads(tree['functions.toml'].data_stream.read().decode())
        except:
            pass
        else:
            functions = {}
            for func in Function.load_many(funcs_toml):
                functions[func.addr] = func
            s.functions = functions

        # load comments
        try:
            comments_toml = toml.loads(tree['comments.toml'].data_stream.read().decode())
        except:
            pass
        else:
            comments = {}
            for comm in Comment.load_many(comments_toml):
                comments[comm.addr] = comm.comment
            s.comments = SortedDict(comments)

        # load patches
        try:
            patches_toml = toml.loads(tree['patches.toml'].data_stream.read().decode())
        except:
            pass
        else:
            patches = {}
            for patch in Patch.load_many(patches_toml):
                patches[patch.offset] = patch
            s.patches = SortedDict(patches)

        # load stack variables
        for func_addr in s.functions:
            try:
                # TODO use unrebased address for more durability
                svs_toml = toml.loads(tree[os.path.join('stack_vars', '%08x.toml' % func_addr)].data_stream.read().decode())
            except:
                pass
            else:
                svs = list(StackVariable.load_many(svs_toml))
                d = dict((v.stack_offset, v) for v in svs)
                if svs:
                    s.stack_variables[svs[0].func_addr] = d

        # clear the dirty bit
        s._dirty = False

        return s

    def copy_state(self, target_state=None):
        if target_state == None:
            print("Cannot copy an empty state (state == None)")
            return

        self.functions = target_state.functions.copy()
        self.comments = target_state.comments.copy()
        self.stack_variables = target_state.stack_variables.copy()
        self.patches = target_state.patches.copy()
        
    def save(self):
        if self.client is None:
            raise RuntimeError("save(): State.client is None.")
        self.client.save_state(self)

    #
    # Pushers
    #

    @dirty_checker
    def update_metadata(self, last_func_push: str, last_push_time: int):
        pass


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
    def remove_comment(self, addr):
        if addr in self.comments:
            del self.comments[addr]
            return True
        return False

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

    # TODO: it would be better if we stored the function addr with every state object, like comments
    def get_modified_addrs(self):
        """
        Gets ever address that has been touched in the current state.
        Returns a set of those addresses.

        @rtype: Set(int)
        """
        moded_addrs = set()
        # ==== functions ==== #
        for addr in self.functions:
            moded_addrs.add(addr)

        # ==== comments ==== #
        for addr in self.comments:
            moded_addrs.add(addr)

        # ==== stack vars ==== #
        for addr in self.stack_variables:
            moded_addrs.add(addr)

        return moded_addrs
