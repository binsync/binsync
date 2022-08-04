import toml

from binsync.data.artifact import Artifact


class Comment(Artifact):
    __slots__ = (
        "last_change",
        "addr",
        "func_addr",
        "comment",
        "decompiled",

    )

    def __init__(self, addr, comment,  func_addr=None, decompiled=False, last_change=None):
        super(Comment, self).__init__(last_change=last_change)
        self.comment = comment  # type: str
        self.decompiled = decompiled  # TODO: use this in other places!
        self.addr = addr  # type: int
        self.func_addr = func_addr

    def __str__(self):
        return f"<Comment: @{hex(self.addr)} len={len(self.comment)}>"

    def __repr__(self):
        return self.__str__()

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

    def copy(self):
        return Comment(
            self.addr,
            self.comment,
            func_addr=self.func_addr,
            decompiled=self.decompiled,
            last_change=self.last_change
        )

    def nonconflict_merge(self, obj2: "Comment") -> "Comment":
        obj1: "Comment" = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        merge_comment = obj1
        merge_comment.comment += "\n" + obj2.comment
        return merge_comment
