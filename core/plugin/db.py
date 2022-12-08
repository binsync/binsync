from typing import NamedTuple, Optional, Dict, Set
from collections import defaultdict
from pathlib import Path
import json


class _Plugin(NamedTuple):
    interpreter: Optional[Path] = None
    hooks: Set[Path] = []


def _as_json(p: _Plugin) -> Dict:
    return {
        "interpreter" : str(p.interpreter),
        "hooks" : [ str(i) for i in p.hooks ],
    }

def _from_json(j) -> _Plugin:
    return _Plugin(
        interpreter = Path(j["interpreter"]).absolute(),
        hooks = { Path(i).absolute() for i in j["hooks"] },
    )


class _DB:

    def __init__(self, f: Path):
        self._f = f  # A json that maps names to plugins

    def _read(self) -> Dict[str, _Plugin]:
        if not self._f.exists():
            return defaultdict(_Plugin)
        with self._f.open("r") as f:
            d = f.read()
        return defaultdict(_Plugin, { i:_from_json(k) for i,k in json.loads(d).items() })

    def _write(self, d: Dict[str, _Plugin]):
        out: str = json.dumps({ i:_as_json(k) for i,k in d.items() })
        with self._f.open("w") as f:
            f.write(out)

    #
    # Public API
    #

    def get_interpreter(self, decompiler: str) -> Optional[Path]:
        return self._read()[decompiler].interpreter

    def set_interpreter(self, decompiler: str, path: Path) -> None:
        d = self._read()
        d[decompiler] = _Plugin(interpreter=path, hooks=d[decompiler].hooks)
        self._write(d)

    def add_hook(self, decompiler: str, path: Path) -> None:
        d = self._read()
        d[decompiler].hooks.add(path)
        self._write(d)

    def get_hooks(self, decompiler) -> Set[Path]:
        return self._read()[decompiler].hooks

    def remove_hook(self, decompiler: str, path: Path) -> None:
        d = self._read()
        d[decompiler].hooks.remove(path)
        self._write(d)

    def remove_plugin(self, decompiler: str) -> None:
        self._write({i:k for i,k in self._read().items() if i != decompiler})


db = _DB(Path.home() / ".binsync" / "plugins.json")
