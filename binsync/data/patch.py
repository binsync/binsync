import codecs
import toml

from .base import Base


class Patch(Base):
    """
    Describes a patch on the binary code.
    """
    __slots__ = (
        "obj_name",
        "offset",
        "new_bytes",
        "last_change"
    )

    def __init__(self, obj_name, offset, new_bytes, last_change=-1):
        self.obj_name = obj_name
        self.offset = offset
        self.new_bytes = new_bytes
        self.last_change = last_change

    def __getstate__(self):
        return {
            "obj_name": self.obj_name,
            "offset": int(self.offset),
            "new_bytes": codecs.encode(self.new_bytes, "hex"),
            "last_change": self.last_change
        }

    def __setstate__(self, state):
        self.obj_name = state["obj_name"]
        self.offset = state["offset"]
        self.new_bytes = codecs.decode(state["new_bytes"], "hex")
        self.last_change = state["last_change"]

    def __eq__(self, other):
        return (
            isinstance(other, Patch)
            and other.obj_name == self.obj_name
            and other.offset == self.offset
            and other.new_bytes == self.new_bytes
            and other.last_change == self.last_change
        )

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        patch = Patch(None, None, None)
        patch.__setstate__(toml.loads(s))
        return patch

    @classmethod
    def load_many(cls, patches_toml):
        for patch_toml in patches_toml.values():
            patch = Patch(None, None, None)
            try:
                patch.__setstate__(patch_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield patch

    @classmethod
    def dump_many(cls, patches):
        patches_ = {}
        for v in patches.values():
            patches_["%s_%x" % (v.obj_name, v.offset)] = v.__getstate__()
        return patches_
