import logging

from binsync.api import BSArtifactLifter

l = logging.getLogger(name=__name__)


class IDAArtifactLifter(BSArtifactLifter):
    lift_map = {
        "__int64": "long",
        "__int32": "int",
        "__int16": "short",
        "__int8": "char",
    }

    def __init__(self, controller):
        super(IDAArtifactLifter, self).__init__(controller)

    def lift_addr(self, addr: int) -> int:
        return addr

    def lift_type(self, type_str: str) -> str:
        for ida_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ida_t, bs_t)

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        return addr

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset #compat.ida_to_angr_stack_offset(func_addr, offset)
