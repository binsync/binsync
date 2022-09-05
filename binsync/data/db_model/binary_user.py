
from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean, BigInteger

from binsync.data.db_model import get_session
from binsync.data.db_model.base_session import Base

import traceback
import logging
import os

logging.basicConfig()
_l = logging.getLogger("DB")
_l.setLevel(logging.DEBUG)


class SQABinary(Base):
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
                b = session.query(SQABinary).first()
                if b is None:
                    binary_name = os.path.basename(binary_path)
                    binary_size = os.path.getsize(binary_path)
                    b = SQABinary(name=binary_name, path=binary_path, hash=binary_hash, size=binary_size)
                    session.add(b)
                    session.commit()
                    _l.info(f"ADDED {b} to DATABASE")
                else:
                    _l.info(f"FOUND {b} in DATABASE")

                return b.id
        except Exception as ex:
            print("ERROR"*20)
            traceback.print_exc()
            print(ex)


class SQAUser(Base):
    """
    Name of a binary with meta information stored
    """
    username = Column(String(64), nullable=False)
    current_local_user = Column(Boolean, nullable=False, default=False)
    user_username_index = Index('user_username_index', 'username')
    __table_args__ = (UniqueConstraint('username', name='user_username_unique_constraint'),)

    def __init__(self, username):
        self.username = username

    @staticmethod
    def get(username):
        with get_session() as session:
            user = session.query(SQAUser).where(SQAUser.username == username).first()
            return user


    @staticmethod
    def save(username):
        try:
            with get_session() as session:
                session.query(SQAUser).update({SQAUser.current_local_user: False}, synchronize_session=False)
                #update(User).values(User.current_local_user=False)
                user = session.query(SQAUser).first()
                if user is None:
                    user = SQAUser(username)
                    session.add(user)
                    _l.info(f"ADDED {user} to DATABASE")
                else:
                    _l.info(f"FOUND {user} in DATABASE")
                user.current_local_user = True
                session.commit()
        except Exception as ex:
            import traceback
            traceback.print_exc()
            print(ex)
