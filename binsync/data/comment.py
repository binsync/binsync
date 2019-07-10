
import toml

from ..utils import is_py3
from .base import Base

if is_py3():
    unicode = str
    long = int


class Comment(Base):
    """
    :ivar int addr:     Address of the comment.
    :ivar str comment:  Content.
    """

    __slots__ = ('addr', 'comment', )

    def __init__(self, addr, comment):
        self.addr = addr
        self.comment = comment

    def __getstate__(self):
        return {
            'addr': self.addr,
            'comment': self.comment,
        }

    def __setstate__(self, state):
        if not isinstance(state["addr"], (int, long)):
            raise TypeError()
        self.addr = state["addr"]
        self.comment = state["comment"]

    def __eq__(self, other):
        return (isinstance(other, Comment) and
                other.addr == self.addr and
                other.comment == self.comment
                )

    def dump(self):
        return toml.dumps(self.__getstate__())

    @classmethod
    def parse(cls, s):
        comm = Comment(None, None)
        comm.__setstate__(toml.loads(s))
        return comm

    @classmethod
    def load_many(cls, path):
        with open(path, "r") as f:
            data = f.read()
        comms_toml = toml.loads(data)

        for comm_toml in comms_toml.values():
            comm = Comment(None, None)
            try:
                comm.__setstate__(comm_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield comm

    @classmethod
    def dump_many(cls, path, comments):
        comments_ = { }
        for k, v in comments.items():
            if type(v) is cls:
                comments_["%x" % k] = v.__getstate__()
            elif isinstance(v, (str, unicode)):
                comments_["%x" % k] = Comment(k, v).__getstate__()
            else:
                raise TypeError("Unsupported comment type %s." % type(v))
        with open(path, "w") as f:
            toml.dump(comments_, f)
