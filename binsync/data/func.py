import toml
from typing import Dict, Optional

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

    def copy(self):
        return FunctionArgument(self.idx, self.name, self.type_str, self.size, last_change=self.last_change)


class FunctionHeader(Artifact):
    __slots__ = (
        "last_change",
        "name",
        "addr",
        "ret_type",
        "args"
    )

    def __init__(self, name, addr, ret_type=None, args=None, last_change=None):
        super(FunctionHeader, self).__init__(last_change=last_change)
        self.name = name
        self.addr = addr
        self.ret_type = ret_type
        self.args = args or {}

    def __getstate__(self):
        args = {str(idx): arg.__getstate__() for idx, arg in self.args.items()} if self.args else {}

        return {
            "last_change": self.last_change,
            "name": self.name,
            "addr": self.addr,
            "ret_type": self.ret_type,
            "args": args if len(args) > 0 else None,
        }

    def __setstate__(self, state):
        self.last_change = state.get("last_change", None)
        self.name = state.get("name", None)
        self.addr = state["addr"]
        self.ret_type = state.get("ret_type", None)
        args = state.get("args", {})
        self.args = {int(idx, 16): FunctionArgument.parse(toml.dumps(arg)) for idx, arg in args.items()}

    @classmethod
    def parse(cls, s):
        loaded_s = toml.loads(s)
        if len(loaded_s) <= 0:
            return None

        fh = FunctionHeader(None, None)
        fh.__setstate__(toml.loads(s))
        return fh

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        # early exit if the two do not match type
        if not isinstance(other, FunctionHeader):
            for k in ["name", "addr", "ret_type"]:
                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }

            diff_dict["args"] = {idx: arg.diff(None) for idx, arg in self.args.items()}
            return diff_dict

        # metadata
        for k in ["name", "addr", "ret_type"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # args
        diff_dict["args"] = {}
        for idx, self_arg in self.args.items():
            try:
                other_arg = other.args[idx]
            except KeyError:
                other_arg = None

            diff_dict["args"][idx] = self_arg.diff(other_arg)

        for idx, other_arg in other.args.items():
            if idx in diff_dict["args"]:
                continue

            diff_dict["args"][idx] = self.invert_diff(other_arg.diff(None))

        return diff_dict

    def copy(self):
        fh = FunctionHeader(self.name, self.addr, ret_type=self.ret_type, last_change=self.last_change)
        fh.args = {k: v.copy() for k, v in self.args.items()}
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

    The metadata contains info on changes and size. The header holds the return type,
    and arguments (including their types). The stack vars contain StackVariables.
    """

    __slots__ = (
        "last_change",
        "addr",
        "size",
        "header",
        "stack_vars",
    )

    def __init__(self, addr, size, header=None, stack_vars=None, last_change=None):
        super(Function, self).__init__(last_change=last_change)
        self.addr: int = addr
        self.size: int = size
        self.header: Optional[FunctionHeader] = header
        self.stack_vars: Dict[int, StackVariable] = stack_vars or {}

    def __getstate__(self):
        header = self.header.__getstate__() if self.header else None
        stack_vars = {"%x" % offset: stack_var.__getstate__() for offset, stack_var in self.stack_vars.items()} if \
            self.stack_vars else {}

        return {
            "metadata": {
                "addr": self.addr,
                "size": self.size,
                "last_change": self.last_change
            },
            "header": header,
            "stack_vars": stack_vars if len(stack_vars) > 0 else None
        }

    def __setstate__(self, state):
        if not isinstance(state["metadata"]["addr"], int):
            raise TypeError("Unsupported type %s for addr." % type(state["metadata"]["addr"]))

        metadata, header, stack_vars = state["metadata"], state.get("header", None), state.get("stack_vars", {})

        self.addr = metadata["addr"]
        self.size = metadata["size"]
        self.last_change = metadata.get("last_change", None)

        self.header = FunctionHeader.parse(toml.dumps(header)) if header else None

        self.stack_vars = {
            int(off, 16): StackVariable.parse(toml.dumps(stack_var)) for off, stack_var in stack_vars.items()
        } if stack_vars else {}

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, Function):
            # metadata
            for k in ["addr", "size"]:
                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }

            # header
            diff_dict["header"] = self.header.diff(other.header)
            # args
            diff_dict["stack_vars"] = {off: var.diff(None) for off, var in self.stack_vars.items()}
            return diff_dict

        # metadata
        for k in ["addr", "size"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # header
        if self.header:
            diff_dict["header"] = self.header.diff(other.header)
        elif other.header:
            diff_dict["header"] = self.invert_diff(other.header.diff(None))
        else:
            diff_dict["header"] = {"before": None, "after": None}

        # stack vars
        diff_dict["stack_vars"] = {}
        for off, self_var in self.stack_vars.items():
            try:
                other_var = other.stack_vars[off]
            except KeyError:
                other_var = None

            diff_dict["stack_vars"][off] = self_var.diff(other_var)

        for off, other_var in other.stack_vars.items():
            if off in diff_dict["stack_vars"]:
                continue

            diff_dict["stack_vars"][off] = self.invert_diff(other_var.diff(None))

        return diff_dict

    def copy(self):
        func = Function(self.addr, self.size, last_change=self.last_change)
        func.header = self.header.copy() if self.header else None
        func.stack_vars = {k: v.copy() for k, v in self.stack_vars.items()}

        return func

    @classmethod
    def parse(cls, s):
        func = Function(None, None)
        func.__setstate__(s)
        return func

    @classmethod
    def load(cls, func_toml):
        f = Function(None, None)
        f.__setstate__(func_toml)
        return f

    @classmethod
    def from_nonconflicting_merge(cls, func1: "Function", func2: "Function") -> "Function":
        func_diff = func1.diff(func2)
        merge_func = func1.copy()

        if merge_func.header is None:
            merge_func.header = func2.header.copy() if func2.header else None
        elif func2.header is not None:
            header_diff = func_diff["header"]
            # name
            if merge_func.name is None and func2.header.name:
                merge_func.header.name = func2.name

            # type_str
            if merge_func.header.ret_type is None and func2.header.ret_type:
                merge_func.header.ret_type = func2.header.ret_type

            # header args
            args_diff = header_diff["args"]
            # TODO: correct this for when offset numbers differ (IDA sync Binja)
            for off, var in func2.header.args.items():
                # arg differs, and the before is not nonexistent
                if off in args_diff and args_diff[off] and (
                        ("name" in args_diff[off] and args_diff[off]["name"]["before"] is not None)
                        or ("type_str" in args_diff[off] and args_diff[off]["type_str"]["before"] is not None)
                ):
                    continue

                # stack var does not conflict
                merge_func.header.args[off] = var.copy()

        # stack vars
        stack_var_diff = func_diff["stack_vars"]
        for off, var in func2.stack_vars.items():
            # stack var differs, and the before is not nonexistent
            if off in stack_var_diff and stack_var_diff[off] and (
                    ("name" in stack_var_diff[off] and stack_var_diff[off]["name"]["before"] is not None)
                    or ("type" in stack_var_diff[off] and stack_var_diff[off]["type"]["before"] is not None)
            ):
                continue

            # stack var does not conflict
            merge_func.stack_vars[off] = var.copy()

        return merge_func

    #
    # Property Shortcuts (Alias)
    #

    @property
    def name(self):
        return self.header.name if self.header else None

    @name.setter
    def name(self, value):
        # create a header if one does not exist for this function
        if not self.header:
            self.header = FunctionHeader(None, self.addr)
        self.header.name = value

    @property
    def args(self):
        return self.header.args

    def set_stack_var(self, name, off: int, off_type: int, size: int, type_str, last_change):
        self.stack_vars[off] = StackVariable(off, off_type, name, type_str, size, self.addr, last_change=last_change)
