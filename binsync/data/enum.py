from collections import OrderedDict
from typing import Dict

import toml

from binsync.data.artifact import Artifact


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
        en = Enum(None, {})
        en.__setstate__(toml.loads(s))
        return en

    @classmethod
    def load_many(cls, enums_toml):
        for enum_toml in enums_toml.values():
            enum = Enum(None, {})
            try:
                enum.__setstate__(enum_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield enum

    @classmethod
    def dump_many(cls, enums):
        enums_ = {}

        for name, enum in enums.items():
            enums_[name] = enum.__getstate__()
        return enums_
