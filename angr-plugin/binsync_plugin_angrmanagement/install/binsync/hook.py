from pathlib import Path
import site

from angrmanagement.plugins import BasePlugin


class BinSyncPlugin(BasePlugin):
    """
    Controller plugin for BinSync
    """
    def __init__(self, workspace):
        super().__init__(workspace)
        self._real = None
        # Hook binsync
        lib = Path.home() / ".binsync" / "venv" / "lib"
        if not lib.exists():
            return
        site.addsitedir(next(lib.glob("python3.*")) / "site-packages")
        try:
            from binsync_plugin_angrmanagement import BinSyncPlugin
        except ModuleNotFoundError:
            return
        self._real = BinSyncPlugin(workspace)

    def __getattr__(self, item):
        if item != "_real" and self._real is not None:
            try:
                return getattr(self._real, item)
            except AttributeError:
                pass
        return object.__getattribute__(self, item)

    def __setattr__(self, key, value):
        if hasattr(self, "_real") and key != "_real" and self._real is not None:
            try:
                return setattr(self._real, key, value)
            except AttributeError:
                pass
        return object.__setattr__(self, key, value)
