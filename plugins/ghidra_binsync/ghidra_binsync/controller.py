from typing import Optional

from binsync.common import BinSyncController
from binsync.data import (
    Function, FunctionHeader
)

import binsync


class GhidraBinSyncController(BinSyncController):
    def __init__(self):
        """
        TODO: add a real lifter as first arg here
        """
        super(GhidraBinSyncController, self).__init__(None)

    def binary_hash(self) -> str:
        return "temp"

    def active_context(self):
        return Function(0, 0, header=FunctionHeader("", 0))

    def binary_path(self) -> Optional[str]:
        return "tmp"

    def get_func_size(self, func_addr) -> int:
        return 0
