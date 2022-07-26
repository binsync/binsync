import logging

from binsync.common import ArtifactLifter

l = logging.getLogger(name=__name__)


class IDAArtifactLifter(ArtifactLifter):
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
        l.info(f"Lifting {type_str} now...")
        for ida_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ida_t, bs_t)

        l.info(f"=> final type: {type_str}")
        return type_str

    def lift_stack_offset(self, offset: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        return addr

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int) -> int:
        return offset
