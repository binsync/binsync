__version__ = "1.0.0"
import os


if "INVOKED_VIA_BINSYNC_CLI" in os.environ:
    from .install import install, uninstall
else:
    from .binsync_plugin import BinSyncPlugin
