import toml
from typing import List, Dict

from .base import Base


class StructMember:
    """
    Describes a struct member that corresponds to a struct.
    """

    __slots__ = (
        "member_name",
        "offset",
        "type",
        "size",
    )

    def __init__(self, member_name, offset, type_, size):
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

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        sv = StructMember(None, None, None, None)
        sv.__setstate__(toml.loads(s))
        return sv


class Struct(Base):
    """
    Describes a struct
    """

    __slots__ = (
        "name",
        "size",
        "struct_members",
    )

    def __init__(self, name: str, size: int, struct_members: List[StructMember]):
        self.name = name
        self.size = size
        self.struct_members = struct_members

    def __getstate__(self):
        struct_data = {"struct_metadata": {"name": self.name, "size": self.size}}
        for member in self.struct_members:
            struct_data.update({"%x" % member.offset: member.__getstate__()})

        print(struct_data)
        return struct_data

    def __setstate__(self, state):
        struct_members = list()
        for k in state.keys():
            if k == "struct_metadata":
                self.name = state[k]["name"]
                self.size = state[k]["size"]
            else:
                struct_members.append(StructMember.parse(state[k]))

        self.struct_members = struct_members

    def add_struct_member(self, mname, moff, mtype, size):
        self.struct_members.append(StructMember(mname, moff, mtype, size))

    def dump(self):
        return self.__getstate__()

    @classmethod
    def parse(cls, s):
        struct = Struct(None, None, None)
        struct.__setstate__(s)
        return struct

    @classmethod
    def load(cls, struct_toml):
        s = Struct(None, None, None)
        s.__setstate__(struct_toml)








