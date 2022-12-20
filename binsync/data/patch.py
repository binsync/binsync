import codecs

import toml

from binsync.data.artifact import Artifact


class Patch(Artifact):
    """
    Describes a patch on the binary code.
    """
    __slots__ = Artifact.__slots__ + (
        "offset",
        "name",
        "new_bytes",
    )

    def __init__(self, offset, new_bytes, name=None, last_change=None):
        super(Patch, self).__init__(last_change=last_change)
        self.offset = offset
        self.name = name
        self.new_bytes = new_bytes

    def __str__(self):
        return f"<Patch: {self.name}@{hex(self.offset)} len={len(self.new_bytes)}>"

    def __repr__(self):
        return self.__str__()

    def __getstate__(self):
        return {
            "name": self.name,
            "offset": hex(self.offset),
            "new_bytes": codecs.encode(self.new_bytes, "hex"),
            "last_change": self.last_change
        }

    def __setstate__(self, state):
        self.name = state["name"]
        self.offset = int(state["offset"], 16)
        self.new_bytes = codecs.decode(state["new_bytes"], "hex")
        self.last_change = state.get("last_change", None)

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
            patches_[hex(v.offset)] = v.__getstate__()
        return patches_

    def copy(self):
        return Patch(
            self.offset,
            self.new_bytes,
            name=self.name,
            last_change=self.last_change
        )
