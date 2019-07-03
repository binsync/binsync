
class Base:

    __slots__ = tuple()

    def dump(self):
        raise NotImplementedError()

    @classmethod
    def parse(cls, s):
        raise NotImplementedError()

    @classmethod
    def load_many(cls, base_path):
        raise NotImplementedError()
