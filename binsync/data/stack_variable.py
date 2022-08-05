import toml

from binsync.data.artifact import Artifact


class StackOffsetType:
    BINJA = 0
    IDA = 1
    GHIDRA = 2
    ANGR = 3


class StackVariable(Artifact):
    """
    Describes a stack variable for a given function.
    """

    __slots__ = (
        "last_change",
        "stack_offset",
        "stack_offset_type",
        "name",
        "type",
        "size",
        "addr",
    )

    def __init__(self, stack_offset, offset_type, name, type_, size, addr, last_change=None):
        super(StackVariable, self).__init__(last_change=last_change)
        self.stack_offset = stack_offset  # type: int
        self.stack_offset_type = offset_type  # type: int
        self.name = name  # type: str
        self.type = type_  # type: str
        self.size = size  # type: int
        self.addr = addr  # type: int
        self.last_change = last_change

    def __eq__(self, other):
        # ignore time and offset type
        if isinstance(other, StackVariable):
            return other.stack_offset == self.stack_offset \
                   and other.name == self.name \
                   and other.type == self.type \
                   and other.size == self.size \
                   and other.addr == self.addr
        return False

    def __str__(self):
        return f"<StackVar: {self.type} {self.name}; {hex(self.stack_offset)}@{hex(self.addr)}>"

    def __repr__(self):
        return self.__str__()

    def get_offset(self, offset_type):
        if offset_type == self.stack_offset_type:
            return self.stack_offset
        # conversion required
        if self.stack_offset_type in (StackOffsetType.IDA, StackOffsetType.BINJA, StackOffsetType.ANGR):
            off = self.stack_offset
        else:
            raise NotImplementedError()
        if offset_type in (StackOffsetType.IDA, StackOffsetType.BINJA):
            return off
        else:
            raise NotImplementedError()

    def copy(self):
        return StackVariable(
            self.stack_offset, self.stack_offset_type, self.name, self.type, self.size, self.addr,
            last_change=self.last_change
        )

    @classmethod
    def parse(cls, s):
        sv = StackVariable(None, None, None, None, None, None)
        sv.__setstate__(toml.loads(s))
        return sv

    @classmethod
    def load_many(cls, svs_toml):
        for sv_toml in svs_toml.values():
            sv = StackVariable(None, None, None, None, None, None)
            sv.__setstate__(sv_toml)
            yield sv

    @classmethod
    def dump_many(cls, svs):
        d = { }
        for v in sorted(svs.values(), key=lambda x: x.stack_offset):
            d["%x" % v.stack_offset] = v.__getstate__()
        return d
