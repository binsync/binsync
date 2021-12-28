import toml
from typing import Dict


class Artifact:
    __slots__ = (
        "last_change"
    )

    def __init__(self, last_change=None):
        self.last_change = None

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
        Like a normal == override but we always ignore last_push.

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

    def dump(self) -> str:
        """
        Returns a string in TOML form of the properties of the current artifact. Best used to
        write directly into a file and save as a .toml file.

        @return:
        """
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        """
        Parses a TOML form string.

        @param s:
        @return:
        """
        raise NotImplementedError()
