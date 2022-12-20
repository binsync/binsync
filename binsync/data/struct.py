from typing import Dict, List

import toml

from binsync.data.artifact import Artifact, TomlHexEncoder

import logging
l = logging.getLogger(name=__name__)


class StructMember(Artifact):
    """
    Describes a struct member that corresponds to a struct.
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "offset",
        "type",
        "size",
    )

    def __init__(self, name, offset, type_, size, last_change=None):
        super(StructMember, self).__init__(last_change=last_change)
        self.name: str = name
        self.offset: int = offset
        self.type: str = type_
        self.size: int = size

    def __str__(self):
        return f"<StructMember: {self.type} {self.name}; @{hex(self.offset)}>"

    def __repr__(self):
        self.__str__()

    @classmethod
    def parse(cls, s):
        sm = StructMember(None, None, None, None)
        sm.__setstate__(toml.loads(s))
        return sm

    def copy(self):
        sm = StructMember(
            self.name,
            self.offset,
            self.type,
            self.size
        )

        return sm


class Struct(Artifact):
    """
    Describes a struct
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "size",
        "members",
    )

    def __init__(self, name: str, size: int, members: Dict[int, StructMember], last_change=None):
        super(Struct, self).__init__(last_change=last_change)
        self.name = name
        self.size = size or 0
        self.members: Dict[int, StructMember] = members

    def __str__(self):
        return f"<Struct: {self.name} membs={len(self.members)} ({hex(self.size)})>"

    def __repr__(self):
        return self.__str__()

    def __getstate__(self):
        return {
            "metadata": {
                "name": self.name, "size": self.size, "last_change": self.last_change
            },

            "members": {
                hex(offset): member.__getstate__() for offset, member in self.members.items()
            }
        }

    def __setstate__(self, state):
        metadata = state["metadata"]
        members = state["members"]

        self.name = metadata["name"]
        self.size = metadata["size"]
        self.last_change = metadata.get("last_change", None)

        self.members = {
            int(off, 16): StructMember.parse(toml.dumps(member, encoder=TomlHexEncoder())) for off, member in members.items()
        }

    def add_struct_member(self, mname, moff, mtype, size):
        self.members[moff] = StructMember(mname, moff, mtype, size)

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

        # struct members
        diff_dict["members"] = {}
        for off, member in self.members.items():
            try:
                other_mem = other.members[off]
            except KeyError:
                other_mem = None

            diff_dict["members"][off] = member.diff(other_mem)

        for off, other_mem in other.members.items():
            if off in diff_dict["members"]:
                continue

            diff_dict["members"][off] = self.invert_diff(other_mem.diff(None))

        return diff_dict

    def copy(self):
        members = {offset: member.copy() for offset, member in self.members.items()}
        struct = Struct(self.name, self.size, members, last_change=self.last_change)
        return struct

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

    def nonconflict_merge(self, struct2: "Struct", **kwargs) -> "Struct":
        struct1: "Struct" = self.copy()
        if not struct2 or struct1 == struct2:
            return struct1

        struct_diff = struct1.diff(struct2)
        merge_struct = struct1

        members_diff = struct_diff["members"]
        for off, mem in struct2.members.items():
            # no difference
            if off not in members_diff:
                continue

            mem_diff = members_diff[off]

            # struct member is newly created
            if "before" in mem_diff and mem_diff["before"] is None:
                # check for overlap
                new_mem_size = mem.size
                new_mem_offset = mem.offset

                for off_check in range(new_mem_offset, new_mem_offset + new_mem_size):
                    if off_check in merge_struct.members:
                        break
                else:
                    merge_struct.members[off] = mem.copy()

                continue

            # member differs
            merge_mem = merge_struct.members.get(off, None)
            if not merge_mem:
                merge_mem = mem

            merge_mem = StructMember.nonconflict_merge(merge_mem, mem)
            merge_struct.members[off] = merge_mem

        # compute the new size
        merge_struct.size = sum(mem.size for mem in merge_struct.members.values())
        return merge_struct
