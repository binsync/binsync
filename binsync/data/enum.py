from .artifact import Artifact
from typing import Dict
from collections import OrderedDict
import toml


class Enum(Artifact):
    __slots__ = Artifact.__slots__ + (
        "name",
        "value_map",
    )

    def __init__(self, name, value_map: Dict[str, int], last_change=None):
        super(Enum, self).__init__(last_change=last_change)
        self.name = name
        # sorts map by the int value
        self.value_map = OrderedDict(sorted(value_map.items(), key=lambda kv: kv[1]))

    @classmethod
    def parse(cls, s):
        en = Enum(None, None)
        en.__setstate__(toml.loads(s))
        return en
