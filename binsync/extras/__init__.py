import importlib
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

_l = logging.getLogger(__name__)

# place all required head imports for extras
EXTRAS_AVAILABLE = True
try:
    # AI Extras
    importlib.import_module("dailalib")
except ImportError:
    _l.info("Extras not installed, some features will not be available.")
    EXTRAS_AVAILABLE = False
