import logging
import importlib
import inspect
from typing import Optional

from .controller import (
    BSController
)
from .artifact_lifter import (
    BSArtifactLifter
)
from .type_parser import (
    BSTypeParser, BSType
)
from ..decompilers import BS_SUPPORTED_DECOMPILERS, ANGR_DECOMPILER, BINJA_DECOMPILER, IDA_DECOMPILER, GHIDRA_DECOMPILER

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


def load_decompiler_controller(force_decompiler: str = None, **ctrl_kwargs) -> Optional[BSController]:
    """
    This function is a special API helper that will attempt to detect the decompiler it is running in and
    return the valid BSController for that decompiler. You may also force the chosen controller using any of the strings
    from binsync.decompiler.BS_SUPPORTED_DECOMPILERS

    @param force_decompiler:    The optional string used to override the BSController returned
    @return:                    The BSController associated with the current decompiler env
    """
    if force_decompiler and force_decompiler not in BS_SUPPORTED_DECOMPILERS:
        raise ValueError(f"Unsupported decompiler {force_decompiler}")

    has_ida = False
    has_binja = False
    has_angr = False
    is_ghidra = False

    try:
        importlib.import_module("idaapi")
        has_ida = True
    except ImportError:
        pass
    if has_ida or force_decompiler == IDA_DECOMPILER:
        from binsync.decompilers.ida.controller import IDABSController
        dec_controller = IDABSController(**ctrl_kwargs)
        return dec_controller

    try:
        importlib.import_module("binaryninja")
        has_binja = True
    except ImportError:
        pass
    if has_binja or force_decompiler == BINJA_DECOMPILER:
        from binsync.decompilers.binja.controller import BinjaBSController
        bv = _find_global_in_call_frames('bv')
        dec_controller = BinjaBSController(bv=bv, **ctrl_kwargs)
        return dec_controller

    try:
        importlib.import_module("angrmanagement")
        has_angr = _find_global_in_call_frames('workspace') is not None
    except ImportError:
        pass
    if has_angr or force_decompiler == ANGR_DECOMPILER:
        from binsync.decompilers.angr.controller import AngrBSController
        workspace = _find_global_in_call_frames('workspace')
        dec_controller = AngrBSController(workspace=workspace, **ctrl_kwargs)
        return dec_controller

    # we assume if we are nothing else, then we are Ghidra
    is_ghidra = not(has_ida or has_binja or has_angr)
    if is_ghidra or force_decompiler == GHIDRA_DECOMPILER:
        from binsync.decompilers.ghidra.controller import GhidraBSController
        dec_controller = GhidraBSController(**ctrl_kwargs)
    else:
        raise ValueError("Please use BinSync with our supported decompiler set!")

    return dec_controller


__all__ = [
    "BSController",
    "BSArtifactLifter",
    "BSTypeParser",
    "BSType",
    "BS_SUPPORTED_DECOMPILERS",
    "ANGR_DECOMPILER",
    "BINJA_DECOMPILER",
    "IDA_DECOMPILER",
    "GHIDRA_DECOMPILER",
    "load_decompiler_controller",
]
