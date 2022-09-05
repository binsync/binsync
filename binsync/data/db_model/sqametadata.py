from sqlalchemy.orm import Session
from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean, BigInteger

from binsync.data.db_model import get_session
from binsync.data.db_model.base_session import Base
from binsync.data.db_model.binary_user import SQAUser

from datetime import datetime

import traceback
import logging
import os

logging.basicConfig()
_l = logging.getLogger("DB")
_l.setLevel(logging.DEBUG)


class SQAMetadata(Base):
    """
    Store meta data about the current system
    """
    version = Column(String(64), nullable=False, default=1)
    last_push_time = Column(DateTime, nullable=False, default=datetime.now)
    last_push_artifact_id = Column(String(128), nullable=True)
    last_push_artifact_type = Column(String(128), nullable=True)

    fk_user_id = Column(String(128), ForeignKey(SQAUser.id), nullable=False)

    def __init__(self, version: str, last_push_time: datetime, last_push_artifact: str, last_push_artifact_type: str, user_id: str):
        self.version = version
        self.last_push_time = last_push_time
        self.last_push_artifact_id = last_push_artifact
        self.last_push_artifact_type = last_push_artifact_type
        self.fk_user_id = user_id

    def __repr__(self):
        return f"SQAMetadata (version={self.version}, last_push_time={self.last_push_time} artifact_id={self.last_push_artifact_id} artifact_type={self.last_push_artifact_type})"

    @staticmethod
    def save(metadata):
        try:
            session: Session
            with get_session() as session:
                user = session.query(SQAUser).where(SQAUser.username == metadata["user"]).first()
                if user is None:
                    user_id = SQAUser.save(metadata["user"])
                else:
                    user_id = user.id
                del metadata["user"]
                metadata["last_push_time"] = datetime.fromtimestamp(metadata["last_push_time"])
                metadata["user_id"] = user_id

                db_metadata = session.query(SQAMetadata).first()
                if db_metadata is None:
                    metadata = SQAMetadata(**metadata)
                    session.add(metadata)
                else:
                    metadata.__init__(**metadata)
                session.commit()

        except Exception as ex:
            print(f"{SQAMetadata.__name__} :: " + "ERROR"*10)
            traceback.print_exc()
            print(ex)

