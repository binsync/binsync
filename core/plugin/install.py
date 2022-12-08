from typing import Optional, List
from pathlib import Path
import shutil
import sys
import os

from .db import db


def interpreter(decompiler: str) -> Path:
    rv = db.get_interpreter(decompiler)
    if rv is not None:
        return rv
    while True:
        sys.stdout.write(f"Where is the {decompiler} python interpreter?\n> ")
        sys.stdout.flush()
        where = Path(input().strip())
        if not where.is_file():
            print(f"No file found at: {where}", file=sys.stdout)
        elif not os.access(where, os.X_OK):
            print(f"{where} is not executable")
        else:
            break
    print(f"Decompiler {decompiler} interpreter set to: {where}")
    db.set_interpreter(decompiler, where)
    return where


def _remove(p: Path) -> None:
    (shutil.rmtree if p.is_dir() else os.remove)(p)


def install(decompiler: str, install_d: Path,  *installables: Path):
    for i in installables:
        out = install_d / i.name
        if out.exists():
            _remove(out)
        (shutil.copytree if i.is_dir() else shutil.copy2)(i, out)
        db.add_hook(decompiler, out)


def uninstall(decompiler: str):
    for i in db.get_hooks(decompiler):
        _remove(i)
        db.remove_hook(decompiler, i)
    db.remove_plugin(decompiler)
