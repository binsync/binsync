import logging
from typing import Optional
import inspect

from .controller import (
    BSController
)
from .artifact_lifter import (
    BSArtifactLifter
)
from .type_parser import (
    BSTypeParser, BSType
)

_l = logging.getLogger(__name__)


def _find_global_in_call_frames(global_name, max_frames=10):
    curr_frame = inspect.currentframe()
    outer_frames = inspect.getouterframes(curr_frame, max_frames)
    for frame in outer_frames:
        global_data = frame.frame.f_globals.get(global_name, None)
        if global_data is not None:
            return global_data
    else:
        return None


def load_decompiler_controller(force_decompiler: str = None) -> Optional[BSController]:
    """
    This function is a special API helper that will attempt to detect the decompiler it is running in and
    return the valid BSController for that decompiler. You may also force the chosen controller using the following
    strings: "ida", "binja", "angr", "ghidra".

    @param force_decompiler:    The optional string used to override the BSController returned
    @return:                    The BSController associated with the current decompiler env
    """
    is_ida = False
    is_binja = False
    is_angr = False
    is_ghidra = False

    try:
        import idaapi
        is_ida = True
    except ImportError:
        pass

    try:
        import binaryninja
        is_binja = True
    except ImportError:
        pass

    try:
        import angr
        import angrmanagement
        is_angr = _find_global_in_call_frames('workspace') is not None
    except ImportError:
        pass

    # we assume if we are nothing else, then we are Ghidra
    is_ghidra = not(is_ida or is_binja or is_angr)

    if is_ida or force_decompiler == "ida":
        from binsync.decompilers.ida.controller import IDABSController
        dec_controller = IDABSController()
    elif is_binja or force_decompiler == "binja":
        from binsync.decompilers.binja.controller import BinjaBSController
        bv = _find_global_in_call_frames('bv')
        dec_controller = BinjaBSController(bv=bv)
    elif is_angr or force_decompiler == "angr":
        from binsync.decompilers.angr.controller import AngrBSController
        workspace = _find_global_in_call_frames('workspace')
        dec_controller = AngrBSController(workspace=workspace)
    elif is_ghidra or force_decompiler == "ghidra":
        from binsync.decompilers.ghidra.server.controller import GhidraBSController
        dec_controller = GhidraBSController()
    else:
        raise ValueError("Please use BinSync with our supported decompiler set!")

    return dec_controller
