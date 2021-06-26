import toml

from .base import Base


class Comment(Base):
    """
    :ivar int func_addr:    Address of the comments Function.
    :ivar int addr:         Address of the comment.
    :ivar str comment:      Content.
    :ivar bool decompiled:  True if the comment is in decompilation
    """

    __slots__ = (
        "comment",
        "decompiled",
        "func_addr",
        "addr",
    )

    def __init__(self, func_addr, addr, comment, decompiled=False):
        self.comment = comment  # type: str
        self.decompiled = decompiled  # TODO: use this in other places!
        self.func_addr = func_addr  # type: int
        self.addr = addr  # type: int

    def __getstate__(self):
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        for k in self.__slots__:
            setattr(self, k, state[k])

    def __eq__(self, other):
        if isinstance(other, Comment):
            for k in self.__slots__:
                if getattr(self, k) != getattr(other, k):
                    return False
            return True
        return False

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        comm = Comment(None, None, None)
        comm.__setstate__(toml.loads(s))
        return comm

    @classmethod
    def load_many(cls, comms_toml):
        for comm_toml in comms_toml.values():
            comm = Comment(None, None, None)
            try:
                comm.__setstate__(comm_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield comm

    @classmethod
    def dump_many(cls, comments):
        comments_ = {}
        for v in sorted(comments.values(), key=lambda x: x.addr):
            comments_["%x" % v.addr] = v.__getstate__()
        return comments_
