from typing import Dict

from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean, BigInteger

from binsync.data import Comment
from binsync.data.db_model.binary_user import SQABinary, SQAUser
from binsync.data.db_model import get_session
from binsync.data.db_model.base_session import Base

import traceback
import logging
import os

logging.basicConfig()
_l = logging.getLogger("DB")
_l.setLevel(logging.DEBUG)


class SQAComment(Base):
    """
        Comment added or updated by user
    """

    address = Column(BigInteger, nullable=False)
    comment = Column(Text(), nullable=False)
    decompiled = Column(Boolean, nullable=False, default=False)

    fk_binary_id = Column(String(128), ForeignKey(SQABinary.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(SQAUser.id), nullable=False)

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
    def save_comments(comments: Dict[int, Comment], binary_id: str, user_id: str):

        with get_session() as session:
            session.begin()
            try:
                added = []
                for comment in comments.values():
                    dbcmt = session.query(SQAComment).where(and_(SQAComment.fk_binary_id == binary_id,
                                                                 SQAComment.fk_user_id == user_id,
                                                                 SQAComment.address == comment.addr)).first()
                    if dbcmt is None:
                        dbcmt = SQAComment(comment.addr, comment.comment, comment.decompiled, binary_id, user_id, comment.func_addr)
                        session.add(dbcmt)
                        session.flush()
                        added.append(dbcmt.id)
                    else:
                        print(f"comment = {dbcmt}")

                session.commit()
                _l.info(f"Added/Updated DB Comments {added}")

            except Exception as ex:
                session.rollback()
                traceback.print_exc()
                print(ex)


