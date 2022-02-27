import toml
from typing import List, Dict

from .artifact import Artifact


class StructMember(Artifact):
    """
    Describes a struct member that corresponds to a struct.
    """

    __slots__ = (
        "last_change",
        "member_name",
        "offset",
        "type",
        "size",
    )

    def __init__(self, member_name, offset, type_, size, last_change=None):
        super(StructMember, self).__init__(last_change=last_change)
        self.member_name: str = member_name
        self.offset: int = offset
        self.type: str = type_
        self.size: int = size

    @classmethod
    def parse(cls, s):
        sm = StructMember(None, None, None, None)
        sm.__setstate__(toml.loads(s))
        return sm


class Struct(Artifact):
    """
    Describes a struct
    """

    __slots__ = (
        "last_change",
        "name",
        "size",
        "struct_members",
    )

    def __init__(self, name: str, size: int, struct_members: List[StructMember], last_change=None):
        super(Struct, self).__init__(last_change=last_change)
        self.name = name
        self.size = size
        self.struct_members = struct_members

    def __getstate__(self):
        return {
            "metadata": {
                "name": self.name, "size": self.size, "last_change": self.last_change
            },

            "members": {"%x" % member.offset: member.__getstate__() for member in self.struct_members}
        }

    def __setstate__(self, state):
        metadata = state["metadata"]
        members = state["members"]

        self.name = metadata["name"]
        self.size = metadata["size"]
        self.last_change = metadata.get("last_change", None)

        self.struct_members = [
            StructMember.parse(toml.dumps(member)) for _, member in members.items()
        ]

    def add_struct_member(self, mname, moff, mtype, size):
        self.struct_members.append(StructMember(mname, moff, mtype, size))

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, Struct):
            return diff_dict

        for k in ["name", "size"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # TODO: fix struct members
        diff_dict["struct_members"] = {}

    @classmethod
    def parse(cls, s):
        struct = Struct(None, None, None)
        struct.__setstate__(s)
        return struct

    @classmethod
    def load(cls, struct_toml):
        s = Struct(None, None, None)
        s.__setstate__(struct_toml)
        return s








