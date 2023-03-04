import toml

from binsync.data.artifact import Artifact


class StackVariable(Artifact):
    """
    Describes a stack variable for a given function.
    """

    __slots__ = Artifact.__slots__ + (
        "offset",
        "name",
        "type",
        "size",
        "addr",
    )

    def __init__(self, stack_offset, name, type_, size, addr, last_change=None):
        super(StackVariable, self).__init__(last_change=last_change)
        self.offset = stack_offset  # type: int
        self.name = name  # type: str
        self.type = type_  # type: str
        self.size = size  # type: int
        self.addr = addr  # type: int
        self.last_change = last_change

    def __eq__(self, other):
        # ignore time and offset type
        if isinstance(other, StackVariable):
            return other.offset == self.offset \
                   and other.name == self.name \
                   and other.type == self.type \
                   and other.size == self.size \
                   and other.addr == self.addr
        return False

    def __str__(self):
        return f"<StackVar: {self.type} {self.name}; {hex(self.offset)}@{hex(self.addr)}>"

    def __repr__(self):
        return self.__str__()

    def copy(self):
        return StackVariable(
            self.offset, self.name, self.type, self.size, self.addr,
            last_change=self.last_change
        )

    @classmethod
    def parse(cls, s):
        sv = StackVariable(None, None, None, None, None)
        sv.__setstate__(toml.loads(s))
        return sv

    @classmethod
    def load_many(cls, svs_toml):
        for sv_toml in svs_toml.values():
            sv = StackVariable(None, None, None, None, None)
            sv.__setstate__(sv_toml)
            yield sv

    @classmethod
    def dump_many(cls, svs):
        d = { }
        for v in sorted(svs.values(), key=lambda x: x.offset):
            d[hex(v.offset)] = v.__getstate__()
        return d
