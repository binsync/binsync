
from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean

from sqlalchemy.orm import relationship
from binsync.data.db_model.base_session import Base, get_session
from binsync.data.db_model.binary_user import Binary, User


class Function(Base):
    """
    General data about a particular function
    """
    address = Column(String(32), nullable=False)
    binary_name_index = Index('binary_name_index', 'name')
    size = Column(Integer, nullable=False)
    return_type = Column(String(32), nullable=True)

    fk_binary_id = Column(String(128), ForeignKey(Binary.id), nullable=False)
    #cve_rec = relationship("CVE", back_populates="links_to_cvex")

    def __init__(self, address, size, fk_binary_id, header = None):
        self.address = address
        self.size = size
        self.header = header
        self.fk_binary_id = fk_binary_id

    def __repr__(self):
        return f"Function (addr={self.address}, size={self.size})"

    @staticmethod
    def save(binary_id, user_id, functions):
        with get_session() as session:
            session.begin()
            try:
                db_functions = session.query(Function).where(Function.fk_binary_id == binary_id).all()
                db_dict_functions = {db_function.address: db_function for db_function in db_functions}  # just for Z
                for address, function in functions.items():
                    if address in db_dict_functions:
                        db_function = db_dict_functions[address]
                        db_fi = FunctionInfo.get_(session, db_function.id, user_id)
                        if db_fi.name != function.name and db_fi.is_root:
                            user_fi = FunctionInfo(function.name, db_function.id, is_root=False, fk_user_id = user_id)
                            session.add(user_fi)

                    else:
                        db_function = Function(address, function.size, binary_id)
                        session.add(db_function)
                        session.flush()
                        print(f"\t\t {binary_id=} ,{db_function.id=}")
                        user_fi = FunctionInfo(function.name,  db_function.id, is_root=True, fk_user_id=user_id)
                        session.add(user_fi)
                    if function.header:
                        print(f"THE HEADER= {function.header}")


                session.commit()
            except Exception as ex:
                print("ERROR" * 20)
                import traceback
                traceback.print_exc()
                print(ex)
                session.rollback()


class FunctionInfo(Base):
    """
    Specific data about a particular function
    """
    name = Column(String(32), nullable=False)
    is_root = Column(Boolean, nullable=False, default=False)

    # foreign keys
    fk_function_id = Column(String(128), ForeignKey(Function.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(User.id), nullable=False)

    function_id_index = Index('fk_function_id_index', 'fk_function_id')
    function_name_index = Index('function_name_index', 'name')

    def __init__(self, name, fk_function_id, is_root, fk_user_id):
        self.name = name
        self.fk_function_id = fk_function_id
        self.is_root = is_root
        self.fk_user_id = fk_user_id

    @staticmethod
    def get_(session, fk_function_id, fk_user_id):
        # we could pass in all the function_ids and get all at once for a speed up, if needed
        fiinfos = session.query(FunctionInfo).where(FunctionInfo.fk_function_id == fk_function_id).order_by(FunctionInfo.is_root).all()
        root_fi = None
        user_fi = None
        for fi in fiinfos:
            if fi.is_root:
                root_fi = fi
            elif fi.fk_user_id == fk_user_id:
                user_fi = fi
        return user_fi if user_fi is not None else root_fi

    # @staticmethod
    # def binary_info(binary_path, binary_hash):
    #     _l.info(f"Getting binary info {binary_path=} {binary_hash=}")
    #     try:
    #         with get_session() as session:
    #             b = session.query(Binary).first()
    #             if b is None:
    #                 binary_name = os.path.basename(binary_path)
    #                 binary_size = os.path.getsize(binary_path)
    #                 b = Binary(name=binary_name, path=binary_path, hash=binary_hash, size=binary_size)
    #                 session.add(b)
    #                 session.commit()
    #                 _l.info(f"ADDED {b} to DATABASE")
    #             else:
    #                 _l.info(f"FOUND {b} in DATABASE")
    #             return b.id
    #     except Exception as ex:
    #         print("ERROR"*20)
    #         import traceback
    #         traceback.print_exc()
    #         print(ex)
