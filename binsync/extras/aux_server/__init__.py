import importlib
import logging

__version__ = "1.0.0"

logging.getLogger("angr").setLevel(logging.ERROR)

_l = logging.getLogger(__name__)

try:
    # Server Extras
    importlib.import_module("flask")
except ImportError:
    _l.info("Server extras not installed, some features will not be available.")
