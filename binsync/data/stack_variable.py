import toml

from ..utils import is_py3
from .base import Base

if is_py3():
    unicode = str
    long = int


class StackVariable(Base):
    """
    Describes a stack variable for a given function.
    """

    __slots__ = (
        "func_addr",
        "name",
        "stack_offset",
        "size",
    )

    def __init__(self, stack_offset, name, size, func_addr):
        self.stack_offset = stack_offset  # type: int
        self.name = name  # type: str
        self.size = size  # type: int
        self.func_addr = func_addr  # type: int

    def __getstate__(self):
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        for k in self.__slots__:
            setattr(self, k, state[k])

    def __eq__(self, other):
        if isinstance(other, StackVariable):
            for k in self.__slots__:
                if getattr(self, k) != getattr(other, k):
                    return False
            return True
        return False

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        sv = StackVariable(None, None, None, None)
        sv.__setstate__(toml.loads(s))
        return sv

    @classmethod
    def load_many(cls, path):
        with open(path, "r") as f:
            data = f.read()
        svs_toml = toml.loads(data)

        for sv_toml in svs_toml.values():
            sv = StackVariable(None, None, None, None)
            sv.__setstate__(sv_toml)
            yield sv

    @classmethod
    def dump_many(cls, path, svs):
        d = dict(svs.items())
        with open(path, "w") as f:
            toml.dump(d, f)
