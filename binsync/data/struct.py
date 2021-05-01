import toml
from typing import List

from .base import Base

"""
{
    struc_name:
        {
            member_offset:
                {
                    member_name,
                    type,
                    size
                }    
        }
}
"""


class StructMember(Base):
    """
    Describes a struct member that corresponds to a struct.
    """

    __slots__ = (
        "struct_name",
        "member_name",
        "offset",
        "type",
        "size",
    )

    def __init__(self, struct_name, member_name, offset, type_, size):
        self.structure_name: str = struct_name
        self.member_name: str = member_name
        self.offset: int = offset
        self.type: str = type_
        self.size: int = size

    def __getstate__(self):
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        for k in self.__slots__:
            setattr(self, k, state[k])

    def __eq__(self, other):
        if isinstance(other, StructMember):
            for k in self.__slots__:
                if getattr(self, k) != getattr(other, k):
                    return False
            return True
        return False

    def get_offset(self, offset_type):
        if offset_type == self.stack_offset_type:
            return self.stack_offset
        # conversion required
        if self.stack_offset_type in (StackOffsetType.IDA, StackOffsetType.BINJA):
            off = self.stack_offset
        else:
            raise NotImplementedError()
        if offset_type in (StackOffsetType.IDA, StackOffsetType.BINJA):
            return off
        else:
            raise NotImplementedError()

    def dump(self):
        return toml.dumps(self.__getstate__())

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
