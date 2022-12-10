from ....binsync.common import ArtifactLifter


class BinjaArtifactLifter(ArtifactLifter):
    lift_map = {
        "int64_t": "long",
        "uint64_t": "unsigned long",
        "int32_t": "int",
        "uint32_t": "unsigned int",
        "int16_t": "short",
        "uint16_t": "unsigned short",
        "int8_t": "char",
        "uint8_t": "unsigned char",
    }

    def __init__(self, controller):
        super(BinjaArtifactLifter, self).__init__(controller)

    def lift_addr(self, addr: int) -> int:
        return addr

    def lift_type(self, type_str: str) -> str:
        for bn_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(bn_t, bs_t)

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        return addr

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
