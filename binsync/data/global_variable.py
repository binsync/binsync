from .artifact import Artifact
import toml


class GlobalVariable(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "type_str",
        "size"
    )

    def __init__(self, addr, name, type_str=None, size=0, last_change=None):
        super(GlobalVariable, self).__init__(last_change=last_change)
        self.addr = addr
        self.name = name
        self.type_str = type_str
        self.size = size

    @classmethod
    def parse(cls, s):
        gv = GlobalVariable(None, None)
        gv.__setstate__(toml.loads(s))
        return gv
