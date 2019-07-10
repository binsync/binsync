
import codecs
import toml

from ..utils import is_py3
from .base import Base


if is_py3():
    unicode = str


class Patch(Base):
    """
    Describes a patch on the binary code.
    """
    def __init__(self, obj_name, offset, new_bytes):
        self.obj_name = obj_name
        self.offset = offset
        self.new_bytes = new_bytes

    def __getstate__(self):
        return {
            'obj_name': self.obj_name,
            'offset': int(self.offset),
            # we need to use codecs to be compatible with Python2 and Python3 at the same time
            'new_bytes': codecs.encode(self.new_bytes, "hex"),
        }

    def __setstate__(self, state):
        if isinstance(state['offset'], (str, unicode)):
            state['offset'] = int(state['offset'].rstrip('L'))

        self.obj_name = state['obj_name']
        self.offset = state['offset']
        # we need to use codecs to be compatible with Python2 and Python3 at the same time
        self.new_bytes = codecs.decode(state['new_bytes'], "hex")

    def __eq__(self, other):
        return (isinstance(other, Patch) and
                other.obj_name == self.obj_name and
                other.offset == self.offset and
                other.new_bytes == self.new_bytes
                )

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        patch = Patch(None, None, None)
        patch.__setstate__(toml.loads(s))
        return patch

    @classmethod
    def load_many(cls, path):
        with open(path, "r") as f:
            data = f.read()
        patches_toml = toml.loads(data)

        for patch_toml in patches_toml.values():
            patch = Patch(None, None, None)
            try:
                patch.__setstate__(patch_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield patch

    @classmethod
    def dump_many(cls, path, patches):
        patches_ = { }
        for v in patches.values():
            patches_["%s_%x" % (v.obj_name, v.offset)] = v.__getstate__()
        with open(path, "w") as f:
            toml.dump(patches_, f)
