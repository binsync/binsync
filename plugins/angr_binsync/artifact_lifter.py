from binsync.common import ArtifactLifter

class AngrArtifactLifter(ArtifactLifter):
    """
    TODO: fix me
    """
    def __init__(self, controller):
        super(AngrArtifactLifter, self).__init__(controller)

    def lift_addr(self, addr: int) -> int:
        return self.controller.rebase_addr(addr)

    def lift_type(self, type_str: str) -> str:
        return type_str

    def lift_stack_offset(self, offset: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        return self.controller.rebase_addr(addr, up=True)

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int) -> int:
        return offset
