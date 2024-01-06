__version__ = "4.0.0"


#
# logging
#

import logging
logging.getLogger("binsync").addHandler(logging.NullHandler())
from binsync.loggercfg import Loggers
loggers = Loggers()
del Loggers
del logging


def create_plugin(*args, **kwargs):
    from libbs.api import DecompilerInterface
    from libbs.decompilers import IDA_DECOMPILER, ANGR_DECOMPILER, BINJA_DECOMPILER, GHIDRA_DECOMPILER
    from binsync.controller import BSController

    # first discover the current decompiler and grab the overrides
    current_decompiler = DecompilerInterface.find_current_decompiler()
    if current_decompiler == IDA_DECOMPILER:
        from binsync.interface_overrides.ida import IDABSInterface
        deci_cls = IDABSInterface
    elif current_decompiler == BINJA_DECOMPILER:
        from binsync.interface_overrides.binja import BinjaBSInterface
        deci_cls = BinjaBSInterface
    elif current_decompiler == ANGR_DECOMPILER:
        from binsync.interface_overrides.angr import BSAngrInterface
        deci_cls = BSAngrInterface
    elif current_decompiler == GHIDRA_DECOMPILER:
        from binsync.interface_overrides.ghidra import GhidraBSInterface
        deci_cls = GhidraBSInterface
    else:
        raise ValueError(f"Unknown decompiler {current_decompiler}")

    # now apply the overrides and create a BinSync controller
    if current_decompiler == GHIDRA_DECOMPILER:
        from binsync.interface_overrides.ghidra import start_remote_ui
        # this will block until the user is done using BinSync
        start_remote_ui()
    else:
        return BSController(deci_cls_override=deci_cls)
