from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean



class Binary(Base):
    """
    Name of a binary with meta information stored
    """
    name = Column(String(256), nullable=False)
    binary_name_index = Index('binary_name_index', 'name')
    path = Column(Text(), nullable=False)
    hash = Column(String(128), nullable=False)
    size = Column(Integer, nullable=False)

    def __init__(self, name, path, hash, size):
        self.name = name
        self. path = path
        if isinstance(hash, bytes):
            self.hash = hash.hex()
        else:
            self.hash = hash
        self.size = size

    def __repr__(self):
        return f"Binary (name={self.name}, hash={self.hash})"

    @staticmethod
    def binary_info(binary_path, binary_hash):
        _l.info(f"Getting binary info {binary_path=} {binary_hash=}")
        try:
            with get_session() as session:
                b = session.query(Binary).first()
                if b is None:
                    binary_name = os.path.basename(binary_path)
                    binary_size = os.path.getsize(binary_path)
                    b = Binary(name=binary_name, path=binary_path, hash=binary_hash, size=binary_size)
                    session.add(b)
                    session.commit()
                    _l.info(f"ADDED {b} to DATABASE")
                else:
                    _l.info(f"FOUND {b} in DATABASE")
                return b.id
        except Exception as ex:
            print("ERROR"*20)
            import traceback
            traceback.print_exc()
            print(ex)
