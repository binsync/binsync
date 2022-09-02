
from typing import Dict

from sqlalchemy import create_engine, update, Column, Index, ForeignKey, UniqueConstraint, event, desc, func, or_, and_
from sqlalchemy import DateTime, String, Integer, BigInteger, Text, Float, Enum, Boolean
import enum
from enum import unique
from sqlalchemy.orm import relationship


from binsync.data.db_model.base_session import Base, get_session
from binsync.data.db_model.binary_user import Binary, User
from binsync.data import Struct, GlobalVariable

@unique
class VariableUses(enum.Enum):
    """
    Various variable uses, VariableUses(status_value).name ==> VariableUses(VariableUses.RETURN_VALUE).name == "RETURN_VALUE"
    """
    RETURN_VALUE = 0
    ARGUMENT = 1
    STACK_VARIABLE = 2
    GLOBAL_VARIABLE = 3
    UNKNOWN = 4

@unique
class ComplexityTypes(enum.Enum):
    """
    Complexity of a variable type
    """
    PRIMATIVE = 0
    STRUCTURE = 1
    ARRAY = 2


class Variable(Base):
    """
    General data about a variable
    """
    from binsync.data.db_model.function import Function
    address = Column(BigInteger, nullable=False)

    used_as = Column(Enum(VariableUses), nullable=False)

    fk_function_id = Column(String(128), ForeignKey(Function.id), nullable=True)
    fk_binary_id = Column(String(128), ForeignKey(Binary.id), nullable=True)

    index1 = Index(f'{Base.__tablename__}_fk_function_id_index', 'fk_function_id')
    index2 = Index(f'{Base.__tablename__}_fk_binary_id_index', 'fk_binary_id')

    def __init__(self, address: int, used_as: VariableUses, fk_binary_id: str = None, fk_function_id: str = None):
        self.address = address
        self.used_as = used_as
        self.fk_binary_id = fk_binary_id
        self.fk_function_id = fk_function_id


    def __repr__(self):
        return f"Variable (addr={self.address}, size={self.size}, used_as={self.used_as})"

    @staticmethod
    def save(address: int, used_as: VariableUses, user_id: str, function_id: str = None, binary_id: str = None,
             var_name: str = None, variable_type="void", session=None):
        if variable_type is None:
            return None
        if session is None:
            session = get_session()

        ret_var = session.query(Variable).where(and_(Variable.fk_binary_id == binary_id, Variable.fk_function_id == function_id )).first()
        if ret_var is None:
            ret_var = Variable(address, used_as, fk_function_id=function_id, fk_binary_id=binary_id)
            session.add(ret_var)
            session.flush()

        VariableInfo.save(var_name, variable_type, user_id, ret_var.id, binary_id, session)

    @staticmethod
    def save_list(variables: Dict[int, GlobalVariable], used_as: VariableUses, binary_id: str, user_id: str, session=None):
        if session is None:
            session = get_session()

        for v in variables.values():
            Variable.save(v.addr, used_as, user_id, binary_id=binary_id, var_name=v.name, variable_type="void", session=session)





class VariableInfo(Base):
    """
    Specific data about a particular variable
    """
    name = Column(String(32), nullable=False)
    is_root = Column(Boolean, nullable=False, default=False)

    # foreign keys
    fk_variable_id = Column(String(128), ForeignKey(Variable.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(User.id), nullable=False)
    # used lowercase in quotes b/c Base sets table name to lowercase
    fk_variable_type_id = Column(String(128), ForeignKey("variableinfo.id"), nullable=False)

    index1 = Index(f'{Base.__tablename__}_fk_variable_id_index', 'fk_variable_id')

    __table_args__ = (UniqueConstraint('fk_variable_id', 'fk_user_id', name=f'{Base.__tablename__}_var_user_unqiue_constraint'),)

    def __init__(self, name: str, fk_variable_id: str, fk_variable_type_id: str, is_root: bool, fk_user_id: str):
        self.name = name
        self.fk_variable_id = fk_variable_id
        self.fk_variable_type_id = fk_variable_type_id
        self.is_root = is_root
        self.fk_user_id = fk_user_id

    @staticmethod
    def save(var_name: str, var_type_name: str , user_id: str, variable_id: str, binary_id: str = None, session=None):
        save_new_entry_for_user = False
        if session is None:
            session = get_session()

        if var_name is not None:
            vi_results = session.query(VariableInfo).where(VariableInfo.fk_variable_id == variable_id).all()
            user_found = False
            var_type_id = None
            for r in vi_results:
                if r.is_root and r.name != var_name:
                    save_new_entry_for_user = True
                if r.fk_user_id == user_id:
                    user_found = True
                    if r.name != var_name:
                        r.name = var_name
                        session.add(r)
                        var_type_id = r.fk_variable_type_id
                    break
            if var_type_id is None:
                var_type_id = VariableType.save(var_type_name, 0, binary_id, session=session)


            # if no results then add a root object, else add a
            if len(vi_results) == 0:
                var_info = VariableInfo(var_name, variable_id, var_type_id, is_root=True, fk_user_id=user_id)
                session.add(var_info)
            elif not user_found and save_new_entry_for_user:
                var_info = VariableInfo(var_name, variable_id, var_type_id, is_root=False, fk_user_id=user_id)
                session.add(var_info)

            session.flush()


class VariableType(Base):
    """
    Variable type information
    """
    name = Column(String(32), nullable=False)
    complexity = Column(Enum(ComplexityTypes), nullable=False)
    size = Column(Integer, nullable=False)

    # foreign keys
    #fk_variable_info_id = Column(String(128), ForeignKey(VariableInfo.id, nullable=False))
    fk_binary_id = Column(String(128), ForeignKey(Binary.id), nullable=False)

    index1 = Index(f'{Base.__tablename__}_fk_variable_info_id_index', 'fk_variable_info_id')

    __table_args__ = (UniqueConstraint('name', 'fk_binary_id', name=f'{Base.__tablename__}_name_unqiue_constraint'),)

    def __init__(self, name: str, size: int, complexity: ComplexityTypes, fk_binary_id: str):
        self.name = name
        self.size = size
        self.complexity = complexity
        self.fk_binary_id = fk_binary_id

    @staticmethod
    def save(var_type_name: str, size: int, binary_id: str, var_complexity: ComplexityTypes = ComplexityTypes.PRIMATIVE, session=None):
        if session is None:
            session = get_session()
        print(f"{var_type_name=}, {binary_id=}")
        var_type = session.query(VariableType).where(and_(VariableType.name == var_type_name, VariableType.fk_binary_id == binary_id)).first()
        if var_type is None:
            var_type = VariableType(var_type_name, size, var_complexity, binary_id)
            session.add(var_type)
            session.flush()
        return var_type.id

    @staticmethod
    def build_struct_list(structs):
        struct_list = []
        stack = list(structs.items())
        visited = set()
        while stack:
            k, v = stack.pop()
            for sm in v.values():
                if sm.type in structs:
                    if v.type not in visited:
                        stack.insert(0, (k,v))
                        stack.insert(0, (v.type, structs[v.type]))
                else:
                    print("%s: %s" % (k, v))
            struct_list.append(k)
            visited.add(k)
        print(struct_list)
        return struct_list

    # @staticmethod
    # def bsl(structs, substruct):
    #     preds = []
    #     for k, v in structs.items():
    #         for sm in v.values():
    #             if sm["type"] in structs:
    #                 preds.extend(bsl(structs, structs[v.type]))
    #     return preds



    @staticmethod
    def save_structs(structs: Dict[str, Struct], binary_id: str, user_id: str, session=None):
        if session is None:
            session = get_session()
        print(f"{session=}")
        session.begin()
        try:
            struct_db_ids = {}
            # first build all the variable types of type structure, then add the structure members to each variable type
            for key, struct in structs.items():
                print(f"{key=} {struct.name=} {struct.size}")
                var_type_id = VariableType.save(struct.name, struct.size, binary_id, var_complexity=ComplexityTypes.STRUCTURE, session=session)
                struct_db_ids[key] = var_type_id

            for key, struct in structs.items():
                structure_type_id = struct_db_ids[key]                       # entry created above in first pass
                for offset, sm in struct.struct_members.items():
                    if sm.type in struct_db_ids:  # member variable type
                        member_type_id = struct_db_ids[sm.type]
                    else:
                        member_type = session.query(VariableType).where(and_(VariableType.name == sm.type, VariableType.fk_binary_id == binary_id)).first()
                        if member_type is None:
                            member_type_id = VariableType.save(sm.type, sm.size, binary_id, var_complexity=ComplexityTypes.PRIMATIVE, session=session)
                        else:
                            member_type_id = member_type.id
                        struct_db_ids[sm.type] = member_type_id

                    StructMember.save(offset, structure_type_id, sm.member_name, member_type_id, user_id, session=session)

                    # print(f"\t{sm}")
            session.commit()
        except Exception as ex:
            print("-" * 20 + "[ ERROR under save_structs ]" + "-" * 20)
            print(ex)
            import traceback
            traceback.print_exc()
            session.rollback()


class StructMember(Base):
    """
    A variable from within a struct
    """
    offset = Column(BigInteger, nullable=False)
    #address = Column(BigInteger, nullable=False)

    # foreign keys
    fk_variable_type_id = Column(String(128), ForeignKey(VariableType.id), nullable=False)

    index1 = Index(f'{Base.__tablename__}_fk_variable_type_id_index', 'fk_variable_type_id')

    def __init__(self, offset: int, variable_type_id: str):
        self.offset = offset
        self.fk_variable_type_id = variable_type_id

    @staticmethod
    def save(offset: int, structure_type_id: str, member_name: str, member_type_id, user_id: str, session=None):
        if session is None:
            session = get_session()
        struct_member = session.query(StructMember).where(and_(StructMember.fk_variable_type_id == structure_type_id, StructMember.offset == offset)).first()
        if struct_member is None:
            struct_member = StructMember(offset, structure_type_id)
            session.add(struct_member)
            session.flush()
            StructMemberInfo.save(member_name, struct_member.id, member_type_id, user_id, is_root=True, session=session)
        else:
            StructMemberInfo.save(member_name, struct_member.id, member_type_id, user_id, is_root=False, session=session)



class StructMemberInfo(Base):
    """
    The user added information regarding a struct variable
    """
    name = Column(String(128), nullable=False)
    is_root = Column(Boolean, nullable=False, default=False)

    # foreign keys
    fk_struct_member_id = Column(String(128), ForeignKey(StructMember.id), nullable=False)
    fk_user_id = Column(String(128), ForeignKey(User.id), nullable=False)
    # this variable is of the type, note the recurisve relationship here back to var type
    fk_member_var_type_id = Column(String(128), ForeignKey(VariableType.id), nullable=False)

    index1 = Index(f'{Base.__tablename__}_fk_variable_type_id_index', 'fk_variable_type_id')

    def __init__(self, name: str, struct_member_id: str, member_var_type_id: str, user_id: str, is_root: bool):
        self.name = name
        self.is_root = is_root
        self.fk_struct_member_id = struct_member_id
        self.fk_user_id = user_id
        self.fk_member_var_type_id = member_var_type_id

    @staticmethod
    def save(name: str, struct_member_id: str, member_var_type_id: str, user_id: str, is_root: bool,
             session=None):
        if session is None:
            session = get_session()

        smi = session.query(StructMemberInfo).where(and_(StructMemberInfo.fk_struct_member_id == struct_member_id,
                                                         StructMemberInfo.fk_user_id == user_id)).first()

        if smi is None: # add it
            smi = StructMemberInfo(name, struct_member_id, member_var_type_id, user_id, is_root)
            session.add(smi)
        else:
            smi.name = name
            smi.member_var_type_id = member_var_type_id

        session.flush()

