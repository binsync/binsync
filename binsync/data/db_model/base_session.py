from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from uuid import uuid4


class BBase:
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    id = Column(String(128), primary_key=True, default=lambda: str(uuid4()))
    created_on = Column(DateTime, nullable=False, default=datetime.now)


Base = declarative_base(cls=BBase)