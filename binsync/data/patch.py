import codecs
import toml

from .artifact import Artifact


class Patch(Artifact):
    """
    Describes a patch on the binary code.
    """
    __slots__ = (
        "last_change",
        "offset",
        "obj_name",
        "new_bytes",
    )

    def __init__(self, offset, new_bytes, obj_name=None, last_change=None):
        super(Patch, self).__init__(last_change=last_change)
        self.offset = offset
        self.obj_name = obj_name
        self.new_bytes = new_bytes

    def __getstate__(self):
        return {
            "obj_name": self.obj_name,
            "offset": hex(self.offset),
            "new_bytes": codecs.encode(self.new_bytes, "hex"),
            "last_change": self.last_change
        }

    def __setstate__(self, state):
        self.obj_name = state["obj_name"]
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
            patches_["%s_%x" % (v.obj_name, v.offset)] = v.__getstate__()
        return patches_
