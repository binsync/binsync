from typing import Dict

from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean, BigInteger

from binsync.data import Comment
from binsync.data.db_model.binary_user import Binary, User
from binsync.data.db_model import get_session
from binsync.data.db_model.base_session import Base

import traceback
import logging
import os

logging.basicConfig()
_l = logging.getLogger("DB")
_l.setLevel(logging.DEBUG)


class DBComment(Base):
    """
        Comment added or updated by user
    """

    address = Column(BigInteger, nullable=False)
    comment = Column(Text(), nullable=False)
    decompiled = Column(Boolean, nullable=False, default=False)

    fk_binary_id = Column(String(128), ForeignKey(Binary.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(User.id), nullable=False)

    comment_user_binary_address_index = Index('comment_user_binary_address_index', 'fk_user_id', 'fk_binary_id', 'address')

    # __table_args__ = (UniqueConstraint('username', name='user_username_unique_constraint'),)

    def __init__(self, address: int, comment: str, decompiled: bool, binary_id: str, user_id: str, func_addr: str = None):
        self.address = address
        self.comment = comment
        self.decompiled = decompiled
        self.func_addr = func_addr      # this could be an FK but not sure why and it will require extra db reads on save

        self.fk_binary_id = binary_id
        self.fk_user_id = user_id

    @staticmethod
    def save_comments(comments: Dict[int, Comment], binary_id, user_id):

        with get_session() as session:
            session.begin()
            try:
                for comment in comments.values():
                    dbcmt = session.query(DBComment).where(and_(DBComment.fk_binary_id == binary_id,
                                                                DBComment.fk_user_id == user_id,
                                                                DBComment.address == comment.addr))
                    if dbcmt is None:
                        dbcmt = DBComment(comment.addr, comment.comment, comment.decompiled, binary_id, user_id, comment.func_addr)
                        session.new(dbcmt)

                session.commit()
                _l.info("Added/Updated DB Comments ")

            except Exception as ex:
                session.rollback()
                traceback.print_exc()
                print(ex)


