import toml
from .artifact import Artifact


class Comment(Artifact):
    __slots__ = (
        "last_change",
        "addr",
        "comment",
        "decompiled",

    )

    def __init__(self, addr, comment,  decompiled=False, func_addr=None, last_change=None):
        super(Comment, self).__init__(last_change=last_change)
        self.comment = comment  # type: str
        self.decompiled = decompiled  # TODO: use this in other places!
        self.addr = addr  # type: int

    @classmethod
    def parse(cls, s):
        comm = Comment(None, None)
        comm.__setstate__(toml.loads(s))
        return comm

    @classmethod
    def load_many(cls, comms_toml):
        for comm_toml in comms_toml.values():
            comm = Comment(None, None)
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
