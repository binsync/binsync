from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from uuid import uuid4
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


class BBase:
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    id = Column(String(128), primary_key=True, default=lambda: str(uuid4()))
    created_on = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


Base = declarative_base(cls=BBase)


def get_session():

    db_path = f"{SCRIPT_DIR}/bs.db"
    engine = create_engine(f'sqlite:///{db_path}', echo=False, pool_pre_ping=True)
    if not os.path.exists(db_path):
        Base.metadata.create_all(engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session()  ## create the session object
