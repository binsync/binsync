
from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer,  Text, Float, Enum, Boolean
from typing import Dict

from binsync.data.db_model.base_session import Base, get_session
from binsync.data.db_model.binary_user import SQABinary, SQAUser
from binsync.data import Function


class SQAFunction(Base):
    """
    General data about a particular function
    """
    address = Column(String(32), nullable=False)
    binary_name_index = Index('binary_name_index', 'name')
    size = Column(Integer, nullable=False)
    return_type = Column(String(32), nullable=True)

    fk_binary_id = Column(String(128), ForeignKey(SQABinary.id), nullable=False)
    #cve_rec = relationship("CVE", back_populates="links_to_cvex")

    def __init__(self, address, size, fk_binary_id):
        self.address = address
        self.size = size
        self.fk_binary_id = fk_binary_id

    def __repr__(self):
        return f"Function (addr={self.address}, size={self.size})"

    @staticmethod
    def save(binary_id, user_id, functions: Dict[int, Function]):
        from binsync.data.db_model.variables import SQAVariable, VariableUses
        with get_session() as session:
            session.begin()
            try:
                db_functions = session.query(SQAFunction).where(SQAFunction.fk_binary_id == binary_id).all()
                db_dict_functions = {db_function.address: db_function for db_function in db_functions}  # just for Z
                for address, function in functions.items():

                    if address in db_dict_functions:
                        db_function = db_dict_functions[address]
                    else:
                        db_function = SQAFunction(address, function.size, binary_id)
                        session.add(db_function)
                        session.flush()
                    if function.name is None:
                        function.name = f"func_{function.addr}"
                    print(f"{function.name=} {function.addr}")
                    SQAFunctionInfo.save(function.name, db_function.id, user_id, session)

                    if function.header:
                        return_var_name = f"{function.name}_return_var"
                        SQAVariable.save(address, VariableUses.RETURN_VALUE, user_id, db_function.id, binary_id=binary_id,
                                         var_name=return_var_name, variable_type=function.header.ret_type, session=session)

                    for key, val in function.stack_vars.items():
                        SQAVariable.save(val.addr, VariableUses.STACK_VARIABLE, user_id, db_function.id, binary_id=binary_id,
                                         var_name=val.name, variable_type=val.type,  )
                        print(f"{key=} {val=}")

                session.commit()
            except Exception as ex:
                print("ERROR" * 20)
                import traceback
                traceback.print_exc()
                print(ex)
                session.rollback()


class SQAFunctionInfo(Base):
    """
    Specific data about a particular function
    """
    name = Column(String(32), nullable=False)
    is_root = Column(Boolean, nullable=False, default=False)

    # foreign keys
    fk_function_id = Column(String(128), ForeignKey(SQAFunction.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(SQAUser.id), nullable=False)

    function_id_index = Index('fk_function_id_index', 'fk_function_id')
    function_name_index = Index('function_name_index', 'name')

    def __init__(self, name, fk_function_id, is_root, fk_user_id):

        self.name = name
        self.fk_function_id = fk_function_id
        self.is_root = is_root
        self.fk_user_id = fk_user_id

    @staticmethod
    def save(function_name: str, function_id: str, user_id: str, session):
        user_fi = SQAFunctionInfo.get_(session, function_id, user_id)
        if user_fi is None:
            user_fi = SQAFunctionInfo(function_name, function_id, is_root=True, fk_user_id=user_id)
            session.add(user_fi)
        elif user_fi.name != function_name and user_fi.is_root:
            user_fi = SQAFunctionInfo(function_name, function_id, is_root=False, fk_user_id=user_id)
            session.add(user_fi)
        else:
            user_fi.name = function_name
        session.flush()
        return user_fi.id

    @staticmethod
    def get_(session, fk_function_id, fk_user_id):
        # we could pass in all the function_ids and get all at once for a speed up, if needed
        fiinfos = session.query(SQAFunctionInfo).where(SQAFunctionInfo.fk_function_id == fk_function_id).order_by(SQAFunctionInfo.is_root).all()
        root_fi = None
        user_fi = None
        for fi in fiinfos:
            if fi.is_root:
                root_fi = fi
            elif fi.fk_user_id == fk_user_id:
                user_fi = fi
        return user_fi if user_fi is not None else root_fi
