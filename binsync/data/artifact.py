import toml


class Artifact:

    __slots__ = (
        "last_change"
    )

    def __init__(self, last_change=None):
        self.last_change = None

    def __getstate__(self):
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        for k in self.__slots__:
            setattr(self, k, state.get(k, None))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        for k in self.__slots__:
            if k == "last_change":
                continue

            if getattr(self, k) != getattr(other, k):
                return False

        return True

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        raise NotImplementedError()
