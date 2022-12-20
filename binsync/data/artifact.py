from typing import Dict

import toml
from toml.encoder import TomlEncoder


class TomlHexEncoder(TomlEncoder):
    def __init__(self, _dict=dict, preserve=False):
        super(TomlHexEncoder, self).__init__(_dict, preserve=preserve)
        self.dump_funcs[int] = lambda v: hex(v) if v >= 0 else v


class Artifact:
    __slots__ = (
        "last_change",
    )

    def __init__(self, last_change=None):
        self.last_change = last_change

    def __getstate__(self) -> Dict:
        """
        Returns a dict of all the properties of the artifact. With the key as their name
        and the value as their value.

        @return:
        """
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        """
        Sets all the properties of the artifact given a dict of keys and values.
        Note: the values can also be dicts.

        @param state: Dict
        @return:
        """
        for k in self.__slots__:
            setattr(self, k, state.get(k, None))

    def __eq__(self, other):
        """
        Like a normal == override, but we always ignore last_push.

        @param other: Another Artifact
        @return:
        """
        if not isinstance(other, self.__class__):
            return False

        for k in self.__slots__:
            if k == "last_change":
                continue

            if getattr(self, k) != getattr(other, k):
                return False

        return True

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, self.__class__):
            for k in self.__slots__:
                if k == "last_change":
                    continue

                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }
            return diff_dict

        for k in self.__slots__:
            self_attr, other_attr = getattr(self, k), getattr(other, k)
            if self_attr != other_attr:
                if k == "last_change":
                    continue

                diff_dict[k] = {
                    "before": self_attr,
                    "after": other_attr
                }
        return diff_dict

    def dump(self) -> str:
        """
        Returns a string in TOML form of the properties of the current artifact. Best used to
        write directly into a file and save as a .toml file.

        @return:
        """
        return toml.dumps(self.__getstate__(), encoder=TomlHexEncoder())

    def copy(self) -> "Artifact":
        return None

    @property
    def commit_msg(self) -> str:
        return f"Updated {self}"

    @classmethod
    def parse(cls, s):
        """
        Parses a TOML form string.

        @param s:
        @return:
        """
        raise NotImplementedError()

    @classmethod
    def invert_diff(cls, diff_dict: Dict):
        inverted_diff = {}
        for k, v in diff_dict.items():
            if k == "before":
                inverted_diff["after"] = v
            elif k == "after":
                inverted_diff["before"] = v
            elif isinstance(v, Dict):
                inverted_diff[k] = cls.invert_diff(v)
            else:
                inverted_diff[k] = v

        return inverted_diff

    def nonconflict_merge(self, obj2: "Artifact", **kwargs):
        obj1 = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        obj_diff = obj1.diff(obj2)
        merge_obj = obj1.copy()

        for attr in self.__slots__:
            if attr in obj_diff and obj_diff[attr]["before"] is None:
                setattr(merge_obj, attr, getattr(obj2, attr))

        return merge_obj
