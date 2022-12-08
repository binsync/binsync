from pathlib import Path
from typing import List

from binsync import plugin


_name = "angr-management"


def install():
    root: Path = plugin.interpreter(_name).parent / ".."
    sp: Path = next((root / "lib").glob("python3.*")).resolve() / "site-packages"
    # sp: Path = Path.home() / ".local" / "share" / "angr-management" / "plugins" # TODO: maybe here?
    plugin.install(_name, sp / "angrmanagement" / "plugins", Path(__file__).parent / "binsync")


def uninstall():
    plugin.uninstall(_name)
