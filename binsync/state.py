import time
from typing import List, Dict, Iterable, Union, Optional
import inspect
import logging

import os
from functools import wraps
from collections import defaultdict
import pathlib

from sortedcontainers import SortedDict
import toml
import git

from .data import Function, FunctionHeader, Comment, Patch, StackVariable, GlobalVariable, Enum
from .data.struct import Struct
from .errors import MetadataNotFoundError

l = logging.getLogger(__name__)


class ArtifactType:
    UNSET = None
    FUNCTION = "function"
    STRUCT = "struct"
    PATCH = "patch"
    COMMENT = "comment"
    GLOBAL_VAR = "global variable"
    ENUM = "enum"


def dirty_checker(f):
    @wraps(f)
    def dirtycheck(self, *args, **kwargs):
        r = f(self, *args, **kwargs)
        if r is True:
            self._dirty = True
        return r

    return dirtycheck


def update_last_change(f):
    @wraps(f)
    def _update_last_change(self, *args, **kwargs):
        should_set = kwargs.pop('set_last_change', True)
        artifact = args[0]

        # make a function if one does not exist
        if isinstance(artifact, (FunctionHeader, StackVariable)):
            func = self.get_or_make_function(artifact.addr)

        if not should_set:
            return f(self, *args, **kwargs)
        artifact.last_change = int(time.time())

        # Comment
        if isinstance(artifact, Comment):
            artifact_loc = artifact.addr
            artifact_type = ArtifactType.COMMENT
            # update function its in, if it's in a function
            func = self.find_func_for_addr(artifact.addr)
            if func:
                func.last_change = artifact.last_change

        # Stack Var
        elif isinstance(artifact, StackVariable):
            artifact_loc = artifact.addr
            artifact_type = ArtifactType.FUNCTION
            func.last_change = artifact.last_change

        # Function Header
        elif isinstance(artifact, FunctionHeader):
            artifact_loc = artifact.addr
            artifact_type = ArtifactType.FUNCTION
            func.last_change = artifact.last_change

        # Patch
        elif isinstance(artifact, Patch):
            artifact_loc = artifact.offset
            artifact_type = ArtifactType.PATCH

        # Struct
        elif isinstance(artifact, Struct):
            artifact_loc = artifact.name
            artifact_type = ArtifactType.STRUCT

        # Global Var
        elif isinstance(artifact, GlobalVariable):
            artifact_loc = artifact.addr
            artifact_type = ArtifactType.GLOBAL_VAR

        # Enum
        elif isinstance(artifact, Enum):
            artifact_loc = artifact.name
            artifact_type = ArtifactType.ENUM

        else:
            raise Exception("Undefined Artifact Type!")

        self.last_push_artifact = artifact_loc
        self.last_push_time = artifact.last_change
        self.last_push_artifact_type = artifact_type

        return f(self, *args, **kwargs)

    return _update_last_change


def list_files_in_tree(base_tree: git.Tree):
    """
    Lists all the files in a repo at a given tree

    :param commit: A gitpython Tree object
    """

    file_list = []
    stack = [base_tree]
    while len(stack) > 0:
        tree = stack.pop()
        # enumerate blobs (files) at this level
        for b in tree.blobs:
            file_list.append(b.path)
        for subtree in tree.trees:
            stack.append(subtree)

    return file_list


def add_data(index: git.IndexFile, path: str, data: bytes):
    fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
    pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
    with open(fullpath, 'wb') as fp:
        fp.write(data)
    index.add([fullpath])


def remove_data(index: git.IndexFile, path: str):
    fullpath = os.path.join(os.path.dirname(index.repo.git_dir), path)
    pathlib.Path(fullpath).parent.mkdir(parents=True, exist_ok=True)
    index.remove([fullpath], working_tree=True)


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
        self.last_push_artifact = -1
        self.last_push_artifact_type = -1
        self.last_push_time = -1

        # the client
        self.client = client  # type: Optional[Client]

        # dirty bit
        self._dirty = False  # type: bool

        # data
        self.functions: Dict[int, Function] = {}
        self.comments: Dict[int, Comment] = {}
        self.structs: Dict[str, Struct] = {}
        self.patches: Dict[int, Patch] = SortedDict()
        self.global_vars: Dict[int, GlobalVariable] = {}
        self.enums: Dict[str, Enum] = {}

    def __eq__(self, other):
        if isinstance(other, State):
            return other.functions == self.functions \
                   and other.comments == self.comments \
                   and other.structs == self.structs \
                   and other.patches == self.patches \
                   and other.global_vars == self.global_vars \
                   and other.enums == self.enums
        return False

    @property
    def dirty(self):
        return self._dirty

    def ensure_dir_exists(self, dir_name):
        if not os.path.exists(dir_name):
            os.mkdir(dir_name)
        if not os.path.isdir(dir_name):
            raise RuntimeError("Cannot create directory %s. Maybe it conflicts with an existing file?" % dir_name)

    def dump_metadata(self, index):
        d = {
            "user": self.user,
            "version": self.version,
            "last_push_time": self.last_push_time,
            "last_push_artifact": self.last_push_artifact,
            "last_push_artifact_type": self.last_push_artifact_type,
        }
        add_data(index, 'metadata.toml', toml.dumps(d).encode())

    def dump(self, index: git.IndexFile):
        # dump metadata
        self.dump_metadata(index)

        # dump functions, one file per function in ./functions/
        for addr, func in self.functions.items():
            path = os.path.join('functions', "%08x.toml" % addr)
            add_data(index, path, func.dump().encode())

        # dump structs, one file per struct in ./structs/
        for s_name, struct in self.structs.items():
            path = os.path.join('structs', f"{s_name}.toml")
            add_data(index, path, struct.dump().encode())

        # dump comments
        add_data(index, 'comments.toml', toml.dumps(Comment.dump_many(self.comments)).encode())

        # dump patches
        add_data(index, 'patches.toml', toml.dumps(Patch.dump_many(self.patches)).encode())

        # dump global vars
        add_data(index, 'global_vars.toml', toml.dumps(GlobalVariable.dump_many(self.global_vars)).encode())

        # dump enums
        add_data(index, 'enums.toml', toml.dumps(Enum.dump_many(self.enums)).encode())

    @staticmethod
    def load_metadata(tree):
        return toml.loads(tree['metadata.toml'].data_stream.read().decode())

    @classmethod
    def parse(cls, tree: git.Tree, version=None, client=None):
        s = cls(None, client=client)

        # load metadata
        try:
            metadata = cls.load_metadata(tree)
        except:
            # metadata is not found
            raise MetadataNotFoundError()
        s.user = metadata["user"]

        s.version = version if version is not None else metadata["version"]

        # load functions
        tree_files = list_files_in_tree(tree)
        function_files = [name for name in tree_files if name.startswith("functions")]
        for func_file in function_files:
            try:
                func_toml = toml.loads(tree[func_file].data_stream.read().decode())
            except:
                pass
            else:
                func = Function.load(func_toml)
                s.functions[func.addr] = func

        # load comments
        try:
            comments_toml = toml.loads(tree['comments.toml'].data_stream.read().decode())
        except:
            pass
        else:
            comments = {}
            for comment in Comment.load_many(comments_toml):
                comments[comment.addr] = comment
            s.comments = comments

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

        # load global_vars
        try:
            global_vars_toml = toml.loads(tree['global_vars.toml'].data_stream.read().decode())
        except:
            pass
        else:
            global_vars = {}
            for global_var in GlobalVariable.load_many(global_vars_toml):
                global_vars[global_var.addr] = global_var
            s.global_vars = SortedDict(global_vars)

        # load enums
        try:
            enums_toml = toml.loads(tree['enums.toml'].data_stream.read().decode())
        except:
            pass
        else:
            s.enums = {
                enum.name: enum for enum in Enum.load_many(enums_toml)
            }

        # load structs
        tree_files = list_files_in_tree(tree)
        struct_files = [name for name in tree_files if name.startswith("structs")]
        for struct_file in struct_files:
            try:
                struct_toml = toml.loads(tree[struct_file].data_stream.read().decode())
            except:
                pass
            else:
                struct = Struct.load(struct_toml)
                s.structs[struct.name] = struct

        # clear the dirty bit
        s._dirty = False

        return s

    def copy_state(self, target_state=None):
        if target_state is None:
            l.warning("Cannot copy an empty state (state == None)")
            return

        self.functions = target_state.functions.copy()
        self.comments = target_state.comments.copy()
        self.patches = target_state.patches.copy()
        self.structs = target_state.structs.copy()
        self.global_vars = target_state.global_vars.copy()
        self.enums = target_state.enums.copy()
        
    def save(self):
        if self.client is None:
            raise RuntimeError("save(): State.client is None.")
        self.client.commit_state(self)

    #
    # Setters
    #

    @dirty_checker
    @update_last_change
    def set_function_header(self, func_header: FunctionHeader, set_last_change=True):
        if self.functions[func_header.addr] == func_header:
            return False

        self.functions[func_header.addr].header = func_header
        return True

    @dirty_checker
    @update_last_change
    def set_comment(self, comment: Comment, set_last_change=True):
        if not comment:
            return False

        try:
            old_cmt = self.comments[comment.addr]
        except KeyError:
            old_cmt = None

        if old_cmt != comment:
            self.comments[comment.addr] = comment
            return True

        return False

    @dirty_checker
    @update_last_change
    def set_patch(self, patch, addr, set_last_change=True):
        if not patch:
            return False

        try:
            old_patch = self.patches[addr]
        except KeyError:
            old_patch = None

        if old_patch != patch:
            self.patches[addr] = patch
            return True

        return False

    @dirty_checker
    @update_last_change
    def set_stack_variable(self, variable, offset, func_addr, set_last_change=True):
        if not variable:
            return False

        func = self.get_function(func_addr)
        if not func:
            return False

        try:
            old_var = func.stack_vars[offset]
        except KeyError:
            old_var = None

        if old_var != variable:
            func.stack_vars[offset] = variable
            return True

        return False

    @dirty_checker
    @update_last_change
    def set_struct(self, struct: Struct, old_name: Optional[str], set_last_change=True):
        """
        Sets a struct in the current state. If old_name is not defined (None), then
        this indicates that the struct has not changed names. In that case, simply overwrite the
        internal representation of the struct.

        If the old_name is defined, than a struct has changed names. In that case, delete
        the internal struct data and delete the related .toml file.

        @param struct:
        @param old_name:
        @param set_last_change:
        @return:
        """
        if struct.name in self.structs \
                and self.structs[struct.name] == struct:
            # no updated is required
            return False

        # delete old struct only when we know what it is
        if old_name is not None:
            try:
                del self.structs[old_name]
                # delete the repo toml for the struct
                remove_data(self.client.repo.index, os.path.join('structs', f'{old_name}.toml'))
            except KeyError:
                pass

        # set the new struct
        if struct.name is not None:
            self.structs[struct.name] = struct

    @dirty_checker
    @update_last_change
    def set_global_var(self, gloabl_var: GlobalVariable, set_last_change=True):
        try:
            old_gvar = self.global_vars[gloabl_var.addr]
        except KeyError:
            old_gvar = None

        if old_gvar != gloabl_var:
            self.global_vars[gloabl_var.addr] = gloabl_var
            return True

        return False

    @dirty_checker
    @update_last_change
    def set_enum(self, enum: Enum, set_last_change=True):
        try:
            old_enum = self.enums[enum.name]
        except KeyError:
            old_enum = None

        if old_enum != enum:
            self.enums[enum.name] = enum
            return True

        return False

    #
    # Getters
    #

    def get_or_make_function(self, addr) -> Function:
        try:
            func = self.functions[addr]
        except KeyError:
            self.functions[addr] = Function(addr, 0)
            func = self.functions[addr]

        return func

    def get_function(self, addr) -> Function:
        try:
            func = self.functions[addr]
        except KeyError:
            func = None

        return func

    def get_comment(self, addr) -> Comment:
        try:
            cmt = self.comments[addr]
        except KeyError:
            cmt = None

        return cmt

    def get_comments(self) -> Dict[int, Comment]:
        return self.comments

    def get_func_comments(self, func_addr):
        try:
            func = self.functions[func_addr]
        except KeyError:
            return {}

        return {
            addr: cmt for addr, cmt in self.comments.items() if addr <= func.addr + func.size
        }

    def get_patch(self, addr) -> Patch:
        try:
            patch = self.patches[addr]
        except KeyError:
            patch = None

        return patch

    def get_patches(self) -> Dict[int, Patch]:
        return self.patches

    def get_stack_variable(self, func_addr, offset) -> Optional[StackVariable]:
        func = self.get_function(func_addr)
        if not func:
            return None

        try:
            stack_var = func.stack_vars[offset]
        except KeyError:
            stack_var = None

        return stack_var

    def get_stack_variables(self, func_addr) -> Dict[int, StackVariable]:
        func = self.get_function(func_addr)
        if not func:
            return {}

        return func.stack_vars

    def get_struct(self, struct_name) -> Optional[Struct]:
        try:
            struct = self.structs[struct_name]
        except KeyError:
            struct = None

        return struct

    def get_structs(self) -> Iterable[Struct]:
        return self.structs.values()

    def get_global_var(self, addr):
        try:
            gvar = self.global_vars[addr]
        except KeyError:
            gvar = None

        return gvar

    def get_enum(self, name):
        try:
            enum = self.enums[name]
        except KeyError:
            enum = None

        return enum

    def get_enums(self):
        return self.enums.values()

    def get_last_push_for_artifact_type(self, artifact_type):
        last_change = -1
        artifact = None

        if artifact_type == ArtifactType.FUNCTION:
            for function in self.functions.values():
                if function.last_change > last_change:
                    last_change = function.last_change
                    artifact = function.addr
        elif artifact_type == ArtifactType.STRUCT:
            for struct in self.structs.values():
                if struct.last_change > last_change:
                    last_change = struct.last_change
                    artifact = struct.name
        elif artifact_type == ArtifactType.PATCH:
            for patch in self.patches.values():
                if patch.last_change > last_change:
                    last_change = patch.last_change
                    artifact = patch.offset

        return tuple((artifact, last_change))

    #
    # Utils
    #

    def diff_comments(self, other_comments: Dict[int, Comment], diff_range=None):
        """

        :param other_comments:
        :param diff_range: [start_addr, end_addr]
        :return:
        """
        diff_dict = {}

        for addr, cmt in self.comments.items():
            # if addr is less than start or bigger than end
            if diff_range and (diff_range[0] > addr or addr >= diff_range[1]):
                continue

            try:
                other_cmt = other_comments[addr]
            except KeyError:
                other_cmt = None

            diff_dict[addr] = cmt.diff(other_cmt)

        for addr, cmt in other_comments.items():
            if diff_range and (diff_range[0] > addr or addr >= diff_range[1]):
                continue

            if addr in diff_dict:
                continue

            diff_dict[addr] = cmt.diff(None)

        return diff_dict

    def find_func_for_addr(self, search_addr):
        for func_addr, func in self.functions.items():
            if func.addr <= search_addr < (func.addr + func.size):
                return func
        else:
            return None

    def find_latest_comment_for_func(self, func: Function) -> Optional[Comment]:
        cmts = [cmt for addr, cmt in self.comments.items() if addr <= func.addr + func.size]
        if not cmts:
            return None

        lastest_cmt = max(cmts, key=lambda c: c.last_change if c.last_change else -1)
        return lastest_cmt
