import toml

from binsync.data.artifact import Artifact


class Comment(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "comment",
        "decompiled",

    )

    def __init__(self, addr, comment,  func_addr=None, decompiled=False, last_change=None):
        super(Comment, self).__init__(last_change=last_change)
        if comment:
            self.comment = self.linewrap_comment(comment)

        self.decompiled = decompiled
        self.addr = addr  # type: int
        self.func_addr = func_addr

    def __str__(self):
        return f"<Comment: @{hex(self.addr)} len={len(self.comment)}>"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def linewrap_comment(comment: str, width=80):
        lines = comment.splitlines()
        final_comment = ""

        for line in lines:
            if len(line) < width:
                final_comment += line + "\n"
                continue

            for i, c in enumerate(line):
                if i % width == 0 and i != 0:
                    final_comment += "\n"
                final_comment += c

            final_comment += "\n"

        return final_comment

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
            comments_[hex(v.addr)] = v.__getstate__()
        return comments_

    def copy(self):
        return Comment(
            self.addr,
            self.comment,
            func_addr=self.func_addr,
            decompiled=self.decompiled,
            last_change=self.last_change
        )

    def nonconflict_merge(self, obj2: "Comment", **kwargs) -> "Comment":
        obj1: "Comment" = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        merge_comment = obj1
        return merge_comment
